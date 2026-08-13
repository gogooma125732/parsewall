"""Scanner for preflight-verified plain text and Markdown."""

from ..contract import EvidenceCode, Finding, RiskLevel
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

_TEXT_CHECK = "text-patterns"


def scan_text(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    """Scan a verified text snapshot without reopening the caller's path."""
    try:
        contents = read_verified_text(source, limits)
        findings: list[Finding] = []
        visible_lines: list[str] = []
        for number, line in enumerate(contents.splitlines(), start=1):
            location = f"text:line={number}"
            for anomaly in anomalies_in(line):
                findings.append(
                    Finding(
                        RiskLevel.REVIEW,
                        EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                        location,
                        anomaly,
                    )
                )
            findings.extend(classify_instruction(line, hidden=False, location=location))
            findings.extend(encoded_block_findings(line, location=location))
            visible_lines.append(strip_directional_controls(line))
        return ParserOutput(
            tuple(findings),
            "\n".join(visible_lines),
            frozenset({_TEXT_CHECK}),
            frozenset({_TEXT_CHECK}),
        )
    except (MemoryError, OSError, RuntimeError, TimeoutError, UnicodeError, ValueError) as error:
        return ParserOutput(
            (failure_finding(failure_kind_for_exception(error)),),
            "",
            frozenset({_TEXT_CHECK}),
            frozenset(),
        )
