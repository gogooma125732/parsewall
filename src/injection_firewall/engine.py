"""Pure scanner orchestration over one immutable verified source."""

from dataclasses import dataclass
from pathlib import Path

from .contract import ScanResult
from .derivative import build_derivative
from .limits import ScanLimits
from .parsers.html import scan_html
from .parsers.text import scan_text
from .policy import PolicyDecision, failure_finding, failure_kind_for_exception
from .preflight import VerifiedSource, verify_source


@dataclass(frozen=True, slots=True)
class ScanArtifacts:
    """Closed result plus a low-only in-memory untrusted derivative."""

    result: ScanResult
    derivative_text: str | None


def _failed_result(error: BaseException) -> ScanResult:
    return ScanResult.from_findings((failure_finding(failure_kind_for_exception(error)),))


def _scan_verified(
    source: VerifiedSource, limits: ScanLimits, suffix: str
) -> tuple[ScanResult, str | None]:
    if source.report.findings:
        return ScanResult.from_findings(source.report.findings), None
    if suffix in {".html", ".htm"}:
        output = scan_html(source, limits)
    elif suffix in {".md", ".markdown"}:
        output = scan_text(source, limits, markdown=True)
    elif suffix == ".txt":
        output = scan_text(source, limits, markdown=False)
    else:
        return _failed_result(ValueError("unsupported format")), None
    result = PolicyDecision(output.findings, output.required_checks, output.completed_checks).result()
    return result, output.visible_text


def scan_file(source: Path, limits: ScanLimits | None = None) -> ScanArtifacts:
    """Scan without mutating any caller-controlled output pathname."""
    effective_limits = limits or ScanLimits()
    try:
        with verify_source(source, effective_limits) as verified:
            result, visible_text = _scan_verified(
                verified,
                effective_limits,
                source.suffix.casefold(),
            )
        return ScanArtifacts(result, build_derivative(result, visible_text))
    except Exception as error:  # noqa: BLE001 -- public scanner boundary is fail-closed.
        return ScanArtifacts(_failed_result(error), None)
