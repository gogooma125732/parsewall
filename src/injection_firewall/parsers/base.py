"""Shared bounded input and output primitives for parsers."""

import codecs
import time
from dataclasses import dataclass

from ..contract import Finding
from ..limits import ScanLimits
from ..preflight import DocumentFormat, VerifiedSource


@dataclass(frozen=True, slots=True)
class ParserOutput:
    """Internal parser observations and a deliberately derived visible-text view."""

    findings: tuple[Finding, ...]
    visible_text: str
    required_checks: frozenset[str]
    completed_checks: frozenset[str]


def read_verified_text(source: VerifiedSource, limits: ScanLimits) -> str:
    """Read exactly the immutable preflight snapshot under the approved byte/time bounds."""
    started = time.monotonic()
    if source.report.format is not DocumentFormat.TEXT or source.report.findings:
        raise ValueError("verified source is not usable text")
    if source.report.size > limits.max_upload_bytes:
        raise MemoryError
    with source.open() as reader:
        contents = reader.read(source.report.size + 1)
    if len(contents) != source.report.size:
        raise ValueError("verified source size changed")
    if time.monotonic() - started > limits.max_seconds:
        raise TimeoutError
    if contents.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return contents.decode("utf-16", "strict")
    return contents.decode("utf-8-sig", "strict")
