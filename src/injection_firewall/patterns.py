"""Bounded, payload-free classification helpers for suspicious text."""

import base64
import binascii
import re
import unicodedata
from collections.abc import Callable

from .contract import AnomalyCode, EvidenceCode, Finding, RiskLevel

_BIDI_CONTROLS = frozenset(
    "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff")
_CONTROL_TRANSLATION = str.maketrans({character: None for character in _BIDI_CONTROLS | _ZERO_WIDTH})
_ENCODED_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-"
)
_ENCODED_MINIMUM = 80
_ENCODED_DECODE_MAXIMUM = 8192

INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:(?:all|any)\s+)?(?:previous|prior|above)\s+(?:instructions?|directions?)\b"),
    re.compile(r"\b(?:disregard|override|bypass)\s+(?:the\s+)?(?:previous|prior|system|developer)\b"),
    re.compile(r"\b(?:reveal|show|print|exfiltrate)\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|instructions?)\b"),
    re.compile(r"\byou\s+are\s+now\b"),
)


def _check(check_deadline: Callable[[], None] | None) -> None:
    if check_deadline is not None:
        check_deadline()


def strip_directional_controls(text: str) -> str:
    """Remove invisible directional and zero-width controls from derivatives."""
    return text.translate(_CONTROL_TRANSLATION)


def normalize_visible_text(
    text: str, *, check_deadline: Callable[[], None] | None = None
) -> str:
    """Normalize text while retaining ordinary tab and line-ending structure."""
    normalized = strip_directional_controls(unicodedata.normalize("NFKC", text))
    visible: list[str] = []
    for index, character in enumerate(normalized):
        if index % 256 == 0:
            _check(check_deadline)
        if character in {"\t", "\n", "\r"} or unicodedata.category(character) not in {"Cc", "Cf"}:
            visible.append(character)
    _check(check_deadline)
    return "".join(visible)


def anomalies_in(text: str) -> tuple[AnomalyCode, ...]:
    """Return closed anomaly codes for registered Unicode controls."""
    anomalies: list[AnomalyCode] = []
    if any(character in _BIDI_CONTROLS for character in text):
        anomalies.append(AnomalyCode.BIDI_CONTROL_CHARACTERS)
    if any(character in _ZERO_WIDTH for character in text):
        anomalies.append(AnomalyCode.ZERO_WIDTH_CHARACTERS)
    return tuple(anomalies)


def has_disallowed_controls(text: str) -> bool:
    """Find non-format C0/C1 and other forbidden controls without exposing them."""
    return any(
        character not in {"\t", "\n", "\r"}
        and unicodedata.category(character) in {"Cc", "Cf"}
        for character in text
    )


def classify_instruction(
    text: str,
    *,
    hidden: bool,
    location: str,
    check_deadline: Callable[[], None] | None = None,
) -> tuple[Finding, ...]:
    """Classify instruction-like text after safe Unicode normalization."""
    _check(check_deadline)
    normalized = normalize_visible_text(text).casefold()
    for pattern in INSTRUCTION_PATTERNS:
        _check(check_deadline)
        if pattern.search(normalized):
            return (
                Finding(
                    RiskLevel.QUARANTINE if hidden else RiskLevel.REVIEW,
                    EvidenceCode.HIDDEN_INSTRUCTION_PATTERN
                    if hidden
                    else EvidenceCode.VISIBLE_INSTRUCTION_PATTERN,
                    location,
                    AnomalyCode.DOM_HIDDEN_CONTENT if hidden else None,
                ),
            )
    return ()


def _decode_encoded_block(encoded: str) -> str | None:
    compact = "".join(character for character in encoded if not character.isspace())
    if len(compact) > _ENCODED_DECODE_MAXIMUM or len(compact) % 4 == 1:
        return None
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, altchars=b"-_", validate=True).decode("utf-8", "strict")
    except (binascii.Error, UnicodeDecodeError):
        return None


def encoded_block_findings(
    text: str,
    *,
    location: str,
    check_deadline: Callable[[], None] | None = None,
) -> tuple[Finding, ...]:
    """Flag long encoded-looking runs even when they are malformed or oversized."""
    findings: list[Finding] = []
    candidate: list[str] = []
    payload_length = 0
    whitespace_count = 0
    segment_length = 0
    longest_segment = 0
    has_base64_signal = False

    def flush() -> None:
        nonlocal candidate, payload_length, whitespace_count, segment_length, longest_segment, has_base64_signal
        if payload_length < _ENCODED_MINIMUM:
            candidate = []
            payload_length = 0
            whitespace_count = 0
            segment_length = 0
            longest_segment = 0
            has_base64_signal = False
            return
        _check(check_deadline)
        encoded = "".join(candidate)
        decoded = _decode_encoded_block(encoded) if payload_length <= _ENCODED_DECODE_MAXIMUM else None
        if whitespace_count > payload_length // 2:
            findings.append(
                Finding(
                    RiskLevel.QUARANTINE,
                    EvidenceCode.ENCODED_INSTRUCTION_PATTERN,
                    location,
                    AnomalyCode.LONG_ENCODED_BLOCK,
                )
            )
            candidate = []
            payload_length = 0
            whitespace_count = 0
            segment_length = 0
            longest_segment = 0
            has_base64_signal = False
            return
        if (
            whitespace_count
            and decoded is None
            and not has_base64_signal
            and longest_segment < _ENCODED_MINIMUM
        ):
            candidate = []
            payload_length = 0
            whitespace_count = 0
            segment_length = 0
            longest_segment = 0
            has_base64_signal = False
            return
        is_instruction = decoded is not None and bool(
            classify_instruction(
                decoded,
                hidden=True,
                location=location,
                check_deadline=check_deadline,
            )
        )
        findings.append(
            Finding(
                RiskLevel.QUARANTINE if is_instruction else RiskLevel.REVIEW,
                EvidenceCode.ENCODED_INSTRUCTION_PATTERN,
                location,
                AnomalyCode.LONG_ENCODED_BLOCK,
            )
        )
        candidate = []
        payload_length = 0
        whitespace_count = 0
        segment_length = 0
        longest_segment = 0
        has_base64_signal = False

    for index, character in enumerate(text):
        if index % 256 == 0:
            _check(check_deadline)
        if character in _ENCODED_ALPHABET:
            payload_length += 1
            segment_length += 1
            longest_segment = max(longest_segment, segment_length)
            has_base64_signal = has_base64_signal or character in "+/=_-"
            if len(candidate) < _ENCODED_DECODE_MAXIMUM:
                candidate.append(character)
        elif character.isspace() and payload_length:
            segment_length = 0
            if len(candidate) < _ENCODED_DECODE_MAXIMUM:
                candidate.append(character)
            whitespace_count += 1
        else:
            flush()
    flush()
    return tuple(findings)
