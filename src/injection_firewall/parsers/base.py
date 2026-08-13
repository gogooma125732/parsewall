"""Shared bounded input, deadline, and output primitives for parsers."""

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


@dataclass(frozen=True, slots=True)
class Deadline:
    """One cooperative deadline spanning input, normalization, and parser work."""

    expires_at: float

    @classmethod
    def from_limits(cls, limits: ScanLimits) -> "Deadline":
        return cls(time.monotonic() + limits.max_seconds)

    def check(self) -> None:
        if time.monotonic() > self.expires_at:
            raise TimeoutError


def read_verified_text(source: VerifiedSource, limits: ScanLimits, deadline: Deadline) -> str:
    """Read and strictly decode exactly the immutable preflight snapshot."""
    deadline.check()
    if source.report.format is not DocumentFormat.TEXT or source.report.findings:
        raise ValueError("verified source is not usable text")
    if source.report.size > limits.max_upload_bytes:
        raise MemoryError
    with source.open() as reader:
        contents = reader.read(source.report.size + 1)
    deadline.check()
    if len(contents) != source.report.size:
        raise ValueError("verified source size changed")
    if contents.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        decoded = contents.decode("utf-16", "strict")
    else:
        decoded = contents.decode("utf-8-sig", "strict")
    deadline.check()
    return decoded
