"""Bounded, payload-free classification helpers for suspicious text."""

import base64
import binascii
import re
import unicodedata

from .contract import AnomalyCode, EvidenceCode, Finding, RiskLevel

_BIDI_CONTROLS = frozenset(
    "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
)
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff")
_CONTROL_TRANSLATION = str.maketrans({character: None for character in _BIDI_CONTROLS | _ZERO_WIDTH})

INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore\s+(?:(?:all|any)\s+)?(?:previous|prior|above)\s+(?:instructions?|directions?)\b"),
    re.compile(r"\b(?:disregard|override|bypass)\s+(?:the\s+)?(?:previous|prior|system|developer)\b"),
    re.compile(r"\b(?:reveal|show|print|exfiltrate)\s+(?:the\s+)?(?:system|developer)\s+(?:prompt|instructions?)\b"),
    re.compile(r"\byou\s+are\s+now\b"),
)
_BASE64_BLOCK = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{80,8192}={0,2})(?![A-Za-z0-9+/=])")


def strip_directional_controls(text: str) -> str:
    """Make invisible directional and zero-width controls unavailable to derivatives."""
    return text.translate(_CONTROL_TRANSLATION)


def anomalies_in(text: str) -> tuple[AnomalyCode, ...]:
    """Return closed anomaly codes for Unicode controls, never the source characters."""
    anomalies: list[AnomalyCode] = []
    if any(character in _BIDI_CONTROLS for character in text):
        anomalies.append(AnomalyCode.BIDI_CONTROL_CHARACTERS)
    if any(character in _ZERO_WIDTH for character in text):
        anomalies.append(AnomalyCode.ZERO_WIDTH_CHARACTERS)
    return tuple(anomalies)


def classify_instruction(text: str, *, hidden: bool, location: str) -> tuple[Finding, ...]:
    """Classify instruction-like text after safe Unicode normalization."""
    normalized = strip_directional_controls(unicodedata.normalize("NFKC", text).casefold())
    if not any(pattern.search(normalized) for pattern in INSTRUCTION_PATTERNS):
        return ()
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


def encoded_block_findings(text: str, *, location: str) -> tuple[Finding, ...]:
    """Detect bounded base64 blocks, escalating those whose decoded view is instructional."""
    findings: list[Finding] = []
    for match in _BASE64_BLOCK.finditer(text):
        encoded = match.group(1)
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("utf-8", "strict")
        except (binascii.Error, UnicodeDecodeError):
            continue
        instruction = classify_instruction(decoded, hidden=True, location=location)
        findings.append(
            Finding(
                RiskLevel.QUARANTINE if instruction else RiskLevel.REVIEW,
                EvidenceCode.ENCODED_INSTRUCTION_PATTERN,
                location,
                AnomalyCode.LONG_ENCODED_BLOCK,
            )
        )
    return tuple(findings)
