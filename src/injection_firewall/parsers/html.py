"""Non-executing scanner and visible-text derivative for verified HTML."""

import re
from html.parser import HTMLParser

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..limits import ScanLimits
from ..patterns import (
    anomalies_in,
    classify_instruction,
    encoded_block_findings,
    strip_directional_controls,
)
from ..policy import failure_finding, failure_kind_for_exception
from ..preflight import VerifiedSource
from .base import ParserOutput, read_verified_text

_HTML_CHECK = "html-dom"
_REMOVED_TAGS = frozenset({"script", "style", "iframe", "object", "embed"})
_ACTIVE_TAGS = frozenset({"script", "iframe", "object", "embed"})
_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"})
_EXTERNAL_ATTRIBUTES = frozenset({"action", "background", "cite", "data", "formaction", "href", "poster", "src"})
_EXTERNAL_URL = re.compile(r"^\s*(?:https?:|ftp:|//)", re.IGNORECASE)
_JAVASCRIPT_URL = re.compile(r"^\s*javascript:", re.IGNORECASE)
_CSS_EXTERNAL_URL = re.compile(r"url\(\s*['\"]?\s*(?:https?:|ftp:|//)", re.IGNORECASE)
_CSS_HIDDEN = re.compile(
    r"(?:display\s*:\s*none\b|visibility\s*:\s*hidden\b|opacity\s*:\s*0(?:\D|$)|font-size\s*:\s*0(?:\D|$)|(?:left|right|top|bottom|text-indent)\s*:\s*-\s*(?:[1-9]\d*|0?\.\d+)(?:px|em|rem|%|vw|vh|pt)?)",
    re.IGNORECASE,
)
_CSS_RULE = re.compile(r"([^{}]{1,8192})\{([^{}]{0,8192})\}")
_CSS_CLASS_SELECTOR = re.compile(r"\.([A-Za-z][A-Za-z0-9_-]{0,95})")
_CSS_ID_SELECTOR = re.compile(r"#([A-Za-z][A-Za-z0-9_-]{0,95})")
_CSS_SIMPLE_TAG_SELECTOR = re.compile(r"^([A-Za-z][A-Za-z0-9-]{0,95})(?:[.#][A-Za-z][A-Za-z0-9_-]{0,95})*$")
_STYLE_CONTENT = re.compile(r"<style\b[^>]{0,8192}>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)


class _VisibleHtml(HTMLParser):
    """Tracks only closed observations while deriving visible text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: list[Finding] = []
        self.visible_parts: list[str] = []
        self._node = 0
        self._stack: list[tuple[str, int, bool]] = []
        self._hidden_classes: set[str] = set()
        self._hidden_ids: set[str] = set()
        self._hidden_tags: set[str] = set()
        self._hide_all_following = False

    def _location(self, node: int | None = None) -> str:
        return f"html:node={node if node is not None else max(self._node, 1)}"

    def _add_hidden_anomaly(self, location: str) -> None:
        self.findings.append(
            Finding(
                RiskLevel.REVIEW,
                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                location,
                AnomalyCode.DOM_HIDDEN_CONTENT,
            )
        )

    def _add_active(self, location: str, anomaly: AnomalyCode | None = None) -> None:
        self.findings.append(Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, location, anomaly))

    def _add_external(self, location: str) -> None:
        self.findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.EXTERNAL_REFERENCE_PRESENT, location))

    def _record_hidden_selectors(self, stylesheet: str) -> bool:
        """Remember bounded static CSS selectors that suppress visible text."""
        found = False
        for match in _CSS_RULE.finditer(stylesheet):
            if not _CSS_HIDDEN.search(match.group(2)):
                continue
            found = True
            selectors = match.group(1)
            self._hidden_classes.update(_CSS_CLASS_SELECTOR.findall(selectors))
            self._hidden_ids.update(_CSS_ID_SELECTOR.findall(selectors))
            for selector in selectors.split(","):
                simple_tag = _CSS_SIMPLE_TAG_SELECTOR.fullmatch(selector.strip())
                if simple_tag is not None:
                    self._hidden_tags.add(simple_tag.group(1).casefold())
                elif not _CSS_CLASS_SELECTOR.search(selector) and not _CSS_ID_SELECTOR.search(selector):
                    self._hide_all_following = True
        return found

    def preload_stylesheets(self, contents: str) -> None:
        """Apply static stylesheet visibility before walking DOM order."""
        for match in _STYLE_CONTENT.finditer(contents):
            self._record_hidden_selectors(match.group(1))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._node += 1
        location = self._location(self._node)
        tag = tag.casefold()
        attributes = {name.casefold(): value or "" for name, value in attrs}
        inherited_hidden = bool(self._stack and self._stack[-1][2])
        class_names = attributes.get("class", "").split()
        directly_hidden = (
            "hidden" in attributes
            or attributes.get("aria-hidden", "").casefold() == "true"
            or any(name in self._hidden_classes for name in class_names)
            or attributes.get("id", "") in self._hidden_ids
            or tag in self._hidden_tags
            or self._hide_all_following
        )
        hidden = (
            inherited_hidden
            or tag in _REMOVED_TAGS
            or directly_hidden
        )
        if directly_hidden:
            self._add_hidden_anomaly(location)
        style = attributes.get("style", "")
        if _CSS_HIDDEN.search(style):
            hidden = True
            self._add_hidden_anomaly(location)
        if tag in _ACTIVE_TAGS:
            self._add_active(location, AnomalyCode.SCRIPT_CONTENT if tag == "script" else None)
        if tag == "meta" and attributes.get("http-equiv", "").casefold() == "refresh":
            self._add_active(location)
        if any(name.startswith("on") for name in attributes):
            self._add_active(location)
        for name, value in attributes.items():
            if name in _EXTERNAL_ATTRIBUTES and _EXTERNAL_URL.search(value):
                self._add_external(location)
            if _JAVASCRIPT_URL.search(value):
                self._add_active(location)
        if _CSS_EXTERNAL_URL.search(style):
            self._add_external(location)
        if tag not in _VOID_TAGS:
            self._stack.append((tag, self._node, hidden))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        folded = tag.casefold()
        for index in range(len(self._stack) - 1, -1, -1):
            if self._stack[index][0] == folded:
                del self._stack[index:]
                break

    def handle_data(self, data: str) -> None:
        node = self._stack[-1][1] if self._stack else max(self._node, 1)
        location = self._location(node)
        hidden = bool(self._stack and self._stack[-1][2])
        if self._stack and self._stack[-1][0] == "style":
            if self._record_hidden_selectors(data):
                self._add_hidden_anomaly(location)
            if _CSS_EXTERNAL_URL.search(data):
                self._add_external(location)
        if hidden:
            self.findings.extend(classify_instruction(data, hidden=True, location=location))
            self.findings.extend(encoded_block_findings(data, location=location))
            return
        self.findings.extend(classify_instruction(data, hidden=False, location=location))
        self.findings.extend(encoded_block_findings(data, location=location))
        for anomaly in anomalies_in(data):
            self.findings.append(
                Finding(
                    RiskLevel.REVIEW,
                    EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                    location,
                    anomaly,
                )
            )
        visible = strip_directional_controls(data).strip()
        if visible:
            self.visible_parts.append(visible)

    def handle_comment(self, data: str) -> None:
        self.findings.extend(classify_instruction(data, hidden=True, location=self._location()))
        self.findings.extend(encoded_block_findings(data, location=self._location()))

    def close_output(self) -> ParserOutput:
        return ParserOutput(
            tuple(self.findings),
            " ".join(self.visible_parts),
            frozenset({_HTML_CHECK}),
            frozenset({_HTML_CHECK}),
        )


def scan_html(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    """Scan a verified HTML snapshot without executing, fetching, or reopening it."""
    try:
        contents = read_verified_text(source, limits)
        parser = _VisibleHtml()
        parser.preload_stylesheets(contents)
        parser.feed(contents)
        parser.close()
        return parser.close_output()
    except (MemoryError, OSError, RuntimeError, TimeoutError, UnicodeError, ValueError) as error:
        return ParserOutput(
            (failure_finding(failure_kind_for_exception(error)),),
            "",
            frozenset({_HTML_CHECK}),
            frozenset(),
        )
