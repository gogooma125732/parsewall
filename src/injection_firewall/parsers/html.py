"""Non-executing, fail-closed scanner and derivative for verified HTML."""

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlsplit

import tinycss2  # type: ignore[import-untyped]

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

_HTML_CHECK = "html-dom"
_REMOVED_TAGS = frozenset(
    {"script", "style", "iframe", "object", "embed", "template", "noscript", "title"}
)
_ACTIVE_TAGS = frozenset({"script", "iframe", "object", "embed"})
_VOID_TAGS = frozenset(
    {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}
)
_EXTERNAL_ATTRIBUTES = frozenset(
    {"action", "background", "cite", "data", "formaction", "href", "poster", "src"}
)
_ACTIVE_SCHEMES = frozenset({"data", "file", "javascript", "vbscript"})
_SIMPLE_SELECTOR = re.compile(
    r"^(?:(?P<tag>[A-Za-z][A-Za-z0-9-]{0,95}))?(?P<suffix>(?:[.#][A-Za-z][A-Za-z0-9_-]{0,95})*)$"
)


@dataclass(slots=True)
class _CssVisibility:
    hidden_classes: set[str] = field(default_factory=set)
    hidden_ids: set[str] = field(default_factory=set)
    hidden_tags: set[str] = field(default_factory=set)
    hide_all: bool = False

    def matches(self, tag: str, attributes: list[tuple[str, str]]) -> bool:
        values = {name: value for name, value in attributes}
        return (
            self.hide_all
            or tag in self.hidden_tags
            or values.get("id", "") in self.hidden_ids
            or any(part in self.hidden_classes for part in values.get("class", "").split())
        )


@dataclass(slots=True)
class _Element:
    tag: str
    node: int
    hidden: bool
    hidden_text: list[str] | None


class _StylesheetCollector(HTMLParser):
    """Collect style element text before DOM extraction without evaluating it."""

    def __init__(self, deadline: Deadline) -> None:
        super().__init__(convert_charrefs=True)
        self._deadline = deadline
        self._in_style = False
        self.stylesheets: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._deadline.check()
        if tag.casefold() == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        self._deadline.check()
        if tag.casefold() == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        self._deadline.check()
        if self._in_style:
            self.stylesheets.append(data)


class _VisibleHtml(HTMLParser):
    """Strict HTML walker that retains only safely mapped visible text."""

    def __init__(self, deadline: Deadline) -> None:
        super().__init__(convert_charrefs=True)
        self.deadline = deadline
        self.findings: list[Finding] = []
        self.visible_parts: list[str] = []
        self._node = 0
        self._stack: list[_Element] = []
        self._hidden_buffer_sizes: dict[int, int] = {}
        self.css = _CssVisibility()
        self.suppress_derivative = False

    def _location(self, node: int | None = None) -> str:
        return f"html:node={node if node is not None else max(self._node, 1)}"

    def _add_hidden(self, location: str) -> None:
        self.findings.append(
            Finding(
                RiskLevel.REVIEW,
                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                location,
                AnomalyCode.DOM_HIDDEN_CONTENT,
            )
        )

    def _add_active(self, location: str, anomaly: AnomalyCode | None = None) -> None:
        self.suppress_derivative = True
        self.findings.append(
            Finding(RiskLevel.QUARANTINE, EvidenceCode.ACTIVE_CONTENT_PRESENT, location, anomaly)
        )

    def _add_external(self, location: str) -> None:
        self.suppress_derivative = True
        self.findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.EXTERNAL_REFERENCE_PRESENT, location))

    def _inspect_url(self, value: str, location: str) -> None:
        self.deadline.check()
        value = value.strip()
        if not value:
            return
        parsed = urlsplit(value)
        if parsed.scheme.casefold() in _ACTIVE_SCHEMES:
            self._add_active(location)
        elif value.startswith("//") or parsed.scheme or parsed.netloc or not value.startswith("#"):
            self._add_external(location)

    def _inspect_tokens_for_urls(self, tokens: list[object], location: str) -> None:
        for token in tokens:
            self.deadline.check()
            token_type = getattr(token, "type", "")
            if token_type == "error":
                raise ValueError("invalid CSS token")
            if token_type == "url":
                self._inspect_url(str(getattr(token, "value", "")), location)
            if token_type == "function":
                if getattr(token, "lower_name", "") == "url":
                    arguments = list(getattr(token, "arguments", []))
                    if len(arguments) == 1 and getattr(arguments[0], "type", "") == "string":
                        url_value = str(getattr(arguments[0], "value", ""))
                    else:
                        url_value = tinycss2.serialize(arguments).strip().strip("'\"")
                    self._inspect_url(url_value, location)
                self._inspect_tokens_for_urls(list(getattr(token, "arguments", [])), location)

    @staticmethod
    def _is_zero(tokens: list[object]) -> bool:
        tokens = [token for token in tokens if getattr(token, "type", "") != "whitespace"]
        if len(tokens) != 1:
            return False
        token = tokens[0]
        return getattr(token, "type", "") in {"number", "percentage", "dimension"} and getattr(token, "value", None) == 0

    @staticmethod
    def _has_transparent_color(tokens: list[object]) -> bool:
        for token in tokens:
            if getattr(token, "type", "") == "ident" and getattr(token, "value", "").casefold() == "transparent":
                return True
            if getattr(token, "type", "") == "hash":
                value = str(getattr(token, "value", "")).casefold()
                if (len(value) == 4 and value[-1] == "0") or (len(value) == 8 and value[-2:] == "00"):
                    return True
            if getattr(token, "type", "") == "function":
                arguments = list(getattr(token, "arguments", []))
                slash = next(
                    (index for index, item in enumerate(arguments) if tinycss2.serialize([item]).strip() == "/"),
                    None,
                )
                if slash is not None:
                    alpha = arguments[slash + 1 :]
                elif getattr(token, "lower_name", "") in {"rgba", "hsla"}:
                    alpha = arguments
                else:
                    continue
                numeric = [
                    item for item in alpha if getattr(item, "type", "") in {"number", "percentage"}
                ]
                if (
                    numeric
                    and (slash is not None or len(numeric) == 4)
                    and getattr(numeric[-1], "value", None) == 0
                ):
                    return True
                if slash is not None and not numeric:
                    return True
        return False

    def _has_zero_filter_opacity(self, tokens: list[object]) -> bool:
        for token in tokens:
            if getattr(token, "type", "") != "function":
                continue
            arguments = list(getattr(token, "arguments", []))
            if getattr(token, "lower_name", "") == "opacity" and self._is_zero(arguments):
                return True
            if self._has_zero_filter_opacity(arguments):
                return True
        return False

    @staticmethod
    def _contains_var(tokens: list[object]) -> bool:
        for token in tokens:
            if getattr(token, "type", "") != "function":
                continue
            if getattr(token, "lower_name", "") == "var" or _VisibleHtml._contains_var(
                list(getattr(token, "arguments", []))
            ):
                return True
        return False

    def _declarations_hide(self, declarations: list[object], location: str) -> bool:
        hidden = False
        for declaration in declarations:
            self.deadline.check()
            if getattr(declaration, "type", "") == "error":
                raise ValueError("invalid CSS declaration")
            if getattr(declaration, "type", "") != "declaration":
                continue
            name = str(getattr(declaration, "lower_name", ""))
            value = list(getattr(declaration, "value", []))
            self._inspect_tokens_for_urls(value, location)
            serialized = tinycss2.serialize(value).strip().casefold()
            has_var = self._contains_var(value)
            if has_var and name in {
                "display",
                "visibility",
                "opacity",
                "font-size",
                "color",
                "background-color",
                "transform",
                "left",
                "right",
                "top",
                "bottom",
                "text-indent",
                "filter",
            }:
                self.suppress_derivative = True
                hidden = True
            if (
                (name == "display" and serialized == "none")
                or (name == "visibility" and serialized in {"hidden", "collapse"})
                or (name in {"opacity", "font-size"} and self._is_zero(value))
                or (name in {"color", "background-color"} and self._has_transparent_color(value))
                or (name == "transform" and "translate" in serialized)
                or (name == "filter" and self._has_zero_filter_opacity(value))
            ):
                hidden = True
            if name in {"left", "right", "top", "bottom", "text-indent"}:
                for token in value:
                    if getattr(token, "type", "") in {"dimension", "percentage"} and abs(float(getattr(token, "value", 0))) >= 1000:
                        hidden = True
        return hidden

    def _apply_selector(self, selector_text: str) -> None:
        for selector in selector_text.split(","):
            match = _SIMPLE_SELECTOR.fullmatch(selector.strip())
            if match is None:
                self.css.hide_all = True
                self.suppress_derivative = True
                continue
            tag = match.group("tag")
            if tag:
                self.css.hidden_tags.add(tag.casefold())
            suffix = match.group("suffix")
            for marker, value in re.findall(r"([.#])([A-Za-z][A-Za-z0-9_-]{0,95})", suffix):
                if marker == ".":
                    self.css.hidden_classes.add(value)
                else:
                    self.css.hidden_ids.add(value)

    def apply_stylesheet(self, stylesheet: str, location: str) -> None:
        rules = tinycss2.parse_stylesheet(stylesheet, skip_comments=True, skip_whitespace=True)
        for rule in rules:
            self.deadline.check()
            rule_type = getattr(rule, "type", "")
            if rule_type == "error":
                raise ValueError("invalid CSS stylesheet")
            if rule_type == "at-rule":
                if getattr(rule, "lower_at_keyword", "") != "import":
                    raise ValueError("unsupported CSS at-rule")
                self._add_active(location)
                self._inspect_tokens_for_urls(list(getattr(rule, "prelude", [])), location)
                continue
            if rule_type != "qualified-rule":
                raise ValueError("unsupported CSS rule")
            declarations = tinycss2.parse_declaration_list(
                getattr(rule, "content", []), skip_comments=True, skip_whitespace=True
            )
            if self._declarations_hide(declarations, location):
                self._add_hidden(location)
                self._apply_selector(tinycss2.serialize(getattr(rule, "prelude", [])).strip())

    def preload_stylesheets(self, contents: str) -> None:
        collector = _StylesheetCollector(self.deadline)
        collector.feed(contents)
        collector.close()
        for stylesheet in collector.stylesheets:
            self.deadline.check()
            self.apply_stylesheet(stylesheet, "html:node=1")

    def _inspect_attributes(self, attributes: list[tuple[str, str]], location: str) -> None:
        for name, value in attributes:
            self.deadline.check()
            if name != "style":
                self.findings.extend(
                    classify_instruction(value, hidden=True, location=location, check_deadline=self.deadline.check)
                )
                self.findings.extend(
                    encoded_block_findings(value, location=location, check_deadline=self.deadline.check)
                )
            if name.startswith("on"):
                self._add_active(location)
            if name in _EXTERNAL_ATTRIBUTES:
                self._inspect_url(value, location)
            elif value.strip().casefold().startswith(tuple(f"{scheme}:" for scheme in _ACTIVE_SCHEMES)):
                self._add_active(location)

    def _append_hidden(self, hidden_text: list[str], text: str) -> None:
        """Append bounded normalized hidden text while retaining semantic separation."""
        normalized = normalize_visible_text(text, check_deadline=self.deadline.check)
        buffer_id = id(hidden_text)
        size = self._hidden_buffer_sizes.get(buffer_id, 0) + len(normalized)
        if size > 32_768:
            raise MemoryError
        self._hidden_buffer_sizes[buffer_id] = size
        hidden_text.append(normalized)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.deadline.check()
        self._node += 1
        location = self._location(self._node)
        tag = tag.casefold()
        attributes = [(name.casefold(), value or "") for name, value in attrs]
        if len({name for name, _ in attributes}) != len(attributes):
            raise ValueError("duplicate HTML attribute")
        inherited_hidden = bool(self._stack and self._stack[-1].hidden)
        values = {name: value for name, value in attributes}
        directly_hidden = (
            "hidden" in values
            or values.get("aria-hidden", "").casefold() == "true"
            or self.css.matches(tag, attributes)
        )
        hidden = inherited_hidden or tag in _REMOVED_TAGS or directly_hidden
        if directly_hidden:
            self._add_hidden(location)
        style = values.get("style")
        if style is not None:
            declarations = tinycss2.parse_declaration_list(style, skip_comments=True, skip_whitespace=True)
            if self._declarations_hide(declarations, location):
                hidden = True
                self._add_hidden(location)
        self._inspect_attributes(attributes, location)
        if tag in _ACTIVE_TAGS:
            self._add_active(location, AnomalyCode.SCRIPT_CONTENT if tag == "script" else None)
        if tag == "meta" and values.get("http-equiv", "").casefold() == "refresh":
            self._add_active(location)
        if inherited_hidden and tag in _VOID_TAGS:
            hidden_text = self._stack[-1].hidden_text
            if hidden_text is None:
                raise ValueError("missing hidden text buffer")
            self._append_hidden(hidden_text, " ")
        if tag not in _VOID_TAGS:
            inherited_buffer = self._stack[-1].hidden_text if inherited_hidden else None
            if inherited_hidden and inherited_buffer is not None:
                self._append_hidden(inherited_buffer, " ")
            hidden_text = inherited_buffer if hidden else None
            self._stack.append(_Element(tag, self._node, hidden, hidden_text))
            if hidden and not inherited_hidden:
                self._stack[-1].hidden_text = []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag.casefold() not in _VOID_TAGS:
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        self.deadline.check()
        folded = tag.casefold()
        if not self._stack or self._stack[-1].tag != folded:
            raise ValueError("malformed HTML nesting")
        element = self._stack.pop()
        inherited_hidden = bool(self._stack and self._stack[-1].hidden)
        if element.hidden and not inherited_hidden and element.hidden_text is not None:
            hidden_text = normalize_visible_text(
                "".join(element.hidden_text), check_deadline=self.deadline.check
            )
            self._hidden_buffer_sizes.pop(id(element.hidden_text), None)
            self.findings.extend(
                classify_instruction(
                    hidden_text,
                    hidden=True,
                    location=self._location(element.node),
                    check_deadline=self.deadline.check,
                )
            )
            self.findings.extend(
                encoded_block_findings(
                    hidden_text, location=self._location(element.node), check_deadline=self.deadline.check
                )
            )
        elif element.hidden and inherited_hidden and element.hidden_text is not None:
            self._append_hidden(element.hidden_text, " ")

    def handle_data(self, data: str) -> None:
        self.deadline.check()
        node = self._stack[-1].node if self._stack else max(self._node, 1)
        location = self._location(node)
        hidden = bool(self._stack and self._stack[-1].hidden)
        if hidden:
            hidden_text = self._stack[-1].hidden_text
            if hidden_text is None:
                raise ValueError("missing hidden text buffer")
            self._append_hidden(hidden_text, data)
            self.findings.extend(encoded_block_findings(data, location=location, check_deadline=self.deadline.check))
            return
        self.findings.extend(classify_instruction(data, hidden=False, location=location, check_deadline=self.deadline.check))
        self.findings.extend(encoded_block_findings(data, location=location, check_deadline=self.deadline.check))
        for anomaly in anomalies_in(data):
            self.findings.append(
                Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, location, anomaly)
            )
        if has_disallowed_controls(data):
            self.findings.append(Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH, location))
        visible = normalize_visible_text(data).strip()
        if visible and not self.suppress_derivative:
            self.visible_parts.append(visible)

    def handle_comment(self, data: str) -> None:
        self.deadline.check()
        location = self._location()
        self.findings.extend(classify_instruction(data, hidden=True, location=location, check_deadline=self.deadline.check))
        self.findings.extend(encoded_block_findings(data, location=location, check_deadline=self.deadline.check))

    def handle_decl(self, decl: str) -> None:
        if decl.casefold() == "doctype html":
            return
        raise ValueError("HTML declarations are not supported")

    def unknown_decl(self, data: str) -> None:
        raise ValueError("unknown HTML declaration")

    def handle_pi(self, data: str) -> None:
        raise ValueError("HTML processing instruction")

    def close_output(self) -> ParserOutput:
        self.deadline.check()
        if self._stack:
            raise ValueError("unterminated HTML element")
        for index in range(0, len(self.visible_parts), 64):
            self.deadline.check()
        derivative = "" if self.suppress_derivative else " ".join(self.visible_parts)
        self.deadline.check()
        return ParserOutput(
            tuple(self.findings),
            derivative,
            frozenset({_HTML_CHECK}),
            frozenset({_HTML_CHECK}),
        )


def _failure_output(error: Exception) -> ParserOutput:
    return ParserOutput(
        (failure_finding(failure_kind_for_exception(error)),),
        "",
        frozenset({_HTML_CHECK}),
        frozenset(),
    )


def scan_html(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    """Scan verified HTML without executing code, fetching resources, or reopening it."""
    try:
        deadline = Deadline.from_limits(limits)
        contents = read_verified_text(source, limits, deadline)
        parser = _VisibleHtml(deadline)
        parser.preload_stylesheets(contents)
        parser.feed(contents)
        if parser.rawdata:
            raise ValueError("unterminated HTML lexical input")
        parser.close()
        output = parser.close_output()
        deadline.check()
        return output
    except Exception as error:  # noqa: BLE001 -- public security boundary sanitizes all ordinary failures.
        return _failure_output(error)
