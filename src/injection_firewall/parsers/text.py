"""Scanner for preflight-verified plain text and bounded Markdown constructs."""

import re
from html import unescape
from urllib.parse import urlsplit

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..limits import ScanLimits
from ..patterns import (
    anomalies_in,
    classify_instruction,
    encoded_block_findings,
    has_disallowed_controls,
    normalize_visible_text,
)
from ..policy import failure_finding, failure_kind_for_exception
from ..preflight import VerifiedSource
from .base import Deadline, ParserOutput, read_verified_text

_TEXT_CHECK = "text-patterns"
_MAX_MARKDOWN_TOKEN = 8192
_ACTIVE_SCHEMES = frozenset({"data", "file", "javascript", "vbscript"})
_ACTIVE_HTML_TAGS = frozenset({"script", "iframe", "object", "embed"})
_URL_HTML_ATTRIBUTES = frozenset(
    {"action", "background", "cite", "data", "formaction", "href", "poster", "src"}
)
_ATTRIBUTE = re.compile(
    r"(?is)([A-Za-z_:][A-Za-z0-9:._-]*)(?:\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s>]+)))?"
)


def _label(value: str) -> str:
    """Canonicalize a bounded Markdown label without exposing it in output."""
    return re.sub(r"\\(.)", r"\1", unescape(value)).casefold().strip()


def _unescape_destination(value: str) -> str:
    """Apply bounded Markdown punctuation escapes before URL classification."""
    return re.sub(r"\\([!\"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~])", r"\1", unescape(value))


def _consume_bracket(contents: str, start: int, deadline: Deadline) -> tuple[str, int] | None:
    """Return escaped Markdown bracket content and its closing index."""
    for index in range(start + 1, min(len(contents), start + _MAX_MARKDOWN_TOKEN)):
        if index % 256 == 0:
            deadline.check()
        if contents[index] == "\\":
            continue
        if contents[index] == "]" and (index == start + 1 or contents[index - 1] != "\\"):
            return contents[start + 1 : index], index
    return None


def _consume_parentheses(contents: str, start: int, deadline: Deadline) -> tuple[str, int] | None:
    """Return one bounded Markdown destination while honoring escapes and nesting."""
    depth = 1
    quote = ""
    for index in range(start + 1, min(len(contents), start + _MAX_MARKDOWN_TOKEN)):
        if index % 256 == 0:
            deadline.check()
        character = contents[index]
        if character == "\\":
            continue
        if quote:
            if character == quote:
                quote = ""
            continue
        if character in {"'", '\"'}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return contents[start + 1 : index], index
    return None


def _consume_html_tag(contents: str, start: int, deadline: Deadline) -> tuple[str, int] | None:
    """Return one bounded, quote-aware raw HTML-shaped construct."""
    quote = ""
    for index in range(start + 1, min(len(contents), start + _MAX_MARKDOWN_TOKEN)):
        if index % 256 == 0:
            deadline.check()
        character = contents[index]
        if quote:
            if character == quote:
                quote = ""
        elif character in {"'", '\"'}:
            quote = character
        elif character == ">":
            return contents[start : index + 1], index
    return None


def _destination_finding(destination: str, findings: list[Finding], deadline: Deadline) -> bool:
    """Classify one untrusted link destination without retaining its text."""
    deadline.check()
    value = _unescape_destination(destination.strip()).strip("<>")
    parsed = urlsplit(value)
    if parsed.scheme.casefold() in _ACTIVE_SCHEMES:
        findings.append(Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1"))
        return True
    if value.startswith("//") or parsed.scheme or parsed.netloc:
        findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.EXTERNAL_REFERENCE_PRESENT, "text:line=1"))
        return True
    return False


def _html_findings(token: str, findings: list[Finding], deadline: Deadline) -> tuple[bool, str | None]:
    """Inspect a raw HTML token conservatively without building a DOM derivative."""
    deadline.check()
    suppress = True
    findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
    head = re.match(r"(?is)<\s*/?\s*([A-Za-z][A-Za-z0-9-]*)", token)
    if head is None:
        return suppress, None
    tag = head.group(1).casefold()
    if tag in _ACTIVE_HTML_TAGS:
        findings.append(Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1"))
    hidden_tag = None
    for match in _ATTRIBUTE.finditer(token[head.end() :]):
        deadline.check()
        name = match.group(1).casefold()
        value = match.group(2) or match.group(3) or match.group(4) or ""
        if name.startswith("on"):
            findings.append(Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1"))
        if name in {"hidden", "style", "aria-hidden"}:
            hidden_tag = tag
            findings.append(
                Finding(
                    RiskLevel.REVIEW,
                    EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                    "text:line=1",
                    AnomalyCode.DOM_HIDDEN_CONTENT,
                )
            )
        if name in _URL_HTML_ATTRIBUTES:
            _destination_finding(value, findings, deadline)
    return suppress, hidden_tag


def _reference_definitions(contents: str, deadline: Deadline) -> dict[str, str]:
    """Collect bounded reference definitions before scanning link uses."""
    definitions: dict[str, str] = {}
    line_start = 0
    while line_start < len(contents):
        deadline.check()
        line_end = contents.find("\n", line_start)
        if line_end < 0:
            line_end = len(contents)
        cursor = line_start
        while cursor < line_end and cursor - line_start < 3 and contents[cursor] in {" ", "\t"}:
            cursor += 1
        if cursor >= line_end or contents[cursor] != "[":
            line_start = line_end + 1
            continue
        label = _consume_bracket(contents, cursor, deadline)
        if label is None:
            line_start = line_end + 1
            continue
        raw_label, close = label
        destination_start = close + 1
        if destination_start >= line_end or contents[destination_start] != ":":
            line_start = line_end + 1
            continue
        destination_start += 1
        while destination_start < line_end and contents[destination_start] in {" ", "\t"}:
            destination_start += 1
        end = destination_start
        while end < line_end and contents[end] not in {" ", "\t", "\r", "\n"}:
            end += 1
        if end > destination_start:
            definitions[_label(raw_label)] = contents[destination_start:end]
        line_start = line_end + 1
    return definitions


def _add_markdown_findings(contents: str, findings: list[Finding], deadline: Deadline) -> bool:
    """Boundedly tokenize Markdown links/raw HTML and suppress untrusted derivatives."""
    suppress_derivative = False
    definitions = _reference_definitions(contents, deadline)
    index = 0
    while index < len(contents):
        if index % 256 == 0:
            deadline.check()
        character = contents[index]
        if character == "<":
            token = _consume_html_tag(contents, index, deadline)
            if token is None:
                findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
                suppress_derivative = True
            else:
                raw, end = token
                raw_suppressed, hidden_tag = _html_findings(raw, findings, deadline)
                suppress_derivative = raw_suppressed or suppress_derivative
                if hidden_tag is not None and not raw.lstrip().startswith("</"):
                    closing = re.compile(rf"(?is)</\s*{re.escape(hidden_tag)}\s*>").search(
                        contents, end + 1, min(len(contents), end + 1 + _MAX_MARKDOWN_TOKEN)
                    )
                    if closing is None:
                        findings.append(
                            Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1")
                        )
                    else:
                        body = re.sub(r"(?is)<[^>]{0,8192}>", " ", contents[end + 1 : closing.start()])
                        findings.extend(
                            classify_instruction(
                                body, hidden=True, location="text:line=1", check_deadline=deadline.check
                            )
                        )
                        findings.extend(
                            encoded_block_findings(body, location="text:line=1", check_deadline=deadline.check)
                        )
                index = end
        link_start = index + 1 if character == "!" and index + 1 < len(contents) and contents[index + 1] == "[" else index
        if contents[link_start : link_start + 1] == "[":
            label = _consume_bracket(contents, link_start, deadline)
            if label is None:
                findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
                suppress_derivative = True
            else:
                raw_label, close = label
                cursor = close + 1
                if cursor < len(contents) and contents[cursor] == "(":
                    destination = _consume_parentheses(contents, cursor, deadline)
                    if destination is None:
                        findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
                        suppress_derivative = True
                    else:
                        raw_destination, end = destination
                        suppress_derivative = _destination_finding(raw_destination, findings, deadline) or suppress_derivative
                        index = end
                elif cursor < len(contents) and contents[cursor] == "[":
                    reference = _consume_bracket(contents, cursor, deadline)
                    if reference is None:
                        findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
                        suppress_derivative = True
                    else:
                        raw_reference, end = reference
                        reference_label = _label(raw_reference) or _label(raw_label)
                        if reference_label in definitions:
                            suppress_derivative = _destination_finding(
                                definitions[reference_label], findings, deadline
                            ) or suppress_derivative
                        else:
                            findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
                            suppress_derivative = True
                        index = end
        index += 1
    return suppress_derivative


def _failure_output(error: Exception) -> ParserOutput:
    return ParserOutput(
        (failure_finding(failure_kind_for_exception(error)),),
        "",
        frozenset({_TEXT_CHECK}),
        frozenset(),
    )


def scan_text(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    """Scan a verified text/Markdown snapshot without reopening the caller path."""
    try:
        deadline = Deadline.from_limits(limits)
        contents = read_verified_text(source, limits, deadline)
        findings: list[Finding] = []
        suppress_derivative = _add_markdown_findings(contents, findings, deadline)
        if has_disallowed_controls(contents):
            findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, "text:line=1"))
        for number, line in enumerate(contents.splitlines(), start=1):
            deadline.check()
            location = f"text:line={number}"
            for anomaly in anomalies_in(line):
                findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, location, anomaly))
            findings.extend(classify_instruction(line, hidden=False, location=location, check_deadline=deadline.check))
        encoded_findings = encoded_block_findings(contents, location="text:line=1", check_deadline=deadline.check)
        findings.extend(encoded_findings)
        derivative = "" if suppress_derivative or encoded_findings else normalize_visible_text(
            contents, check_deadline=deadline.check
        )
        deadline.check()
        return ParserOutput(tuple(findings), derivative, frozenset({_TEXT_CHECK}), frozenset({_TEXT_CHECK}))
    except Exception as error:  # noqa: BLE001 -- public security boundary sanitizes all ordinary failures.
        return _failure_output(error)
