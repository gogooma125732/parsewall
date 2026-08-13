"""Scanner for preflight-verified plain text and Markdown."""

import re
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
_RAW_HTML = re.compile(r"<[!?/]?[A-Za-z][^>\r\n]{0,8192}>")
_ACTIVE_HTML = re.compile(r"<\s*(?:script|iframe|object|embed)\b|\son[A-Za-z0-9_-]*\s*=", re.IGNORECASE)
_HIDDEN_HTML = re.compile(r"\b(?:hidden|style|aria-hidden)\s*=", re.IGNORECASE)
_MARKDOWN_LINK = re.compile(
    r"!?\[[^\]\r\n]{0,4096}\]\(\s*(?:<([^>\r\n]{1,8192})>|([^\s)\r\n]{1,8192}))",
)
_ACTIVE_SCHEMES = frozenset({"data", "file", "javascript", "vbscript"})


def _add_markdown_findings(
    contents: str, findings: list[Finding], deadline: Deadline
) -> bool:
    """Scan Markdown links/raw HTML and conservatively suppress their derivative."""
    suppress_derivative = False
    for match in _RAW_HTML.finditer(contents):
        deadline.check()
        suppress_derivative = True
        findings.append(
            Finding(
                RiskLevel.REVIEW,
                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                "text:line=1",
            )
        )
        token = match.group(0)
        if _ACTIVE_HTML.search(token):
            findings.append(
                Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1")
            )
        if _HIDDEN_HTML.search(token):
            findings.append(
                Finding(
                    RiskLevel.REVIEW,
                    EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                    "text:line=1",
                    AnomalyCode.DOM_HIDDEN_CONTENT,
                )
            )
    for match in _MARKDOWN_LINK.finditer(contents):
        deadline.check()
        destination = (match.group(1) or match.group(2) or "").strip()
        parsed = urlsplit(destination)
        if parsed.scheme.casefold() in _ACTIVE_SCHEMES:
            suppress_derivative = True
            findings.append(
                Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, "text:line=1")
            )
        elif destination.startswith("//") or parsed.scheme or parsed.netloc:
            suppress_derivative = True
            findings.append(
                Finding(RiskLevel.REVIEW, EvidenceCode.EXTERNAL_REFERENCE_PRESENT, "text:line=1")
            )
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
        for number, line in enumerate(contents.splitlines(), start=1):
            deadline.check()
            location = f"text:line={number}"
            for anomaly in anomalies_in(line):
                findings.append(
                    Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, location, anomaly)
                )
            if has_disallowed_controls(line):
                findings.append(
                    Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, location)
                )
            findings.extend(
                classify_instruction(line, hidden=False, location=location, check_deadline=deadline.check)
            )
        findings.extend(
            encoded_block_findings(contents, location="text:line=1", check_deadline=deadline.check)
        )
        deadline.check()
        return ParserOutput(
            tuple(findings),
            "" if suppress_derivative else normalize_visible_text(contents),
            frozenset({_TEXT_CHECK}),
            frozenset({_TEXT_CHECK}),
        )
    except Exception as error:  # noqa: BLE001 -- public security boundary sanitizes all ordinary failures.
        return _failure_output(error)
