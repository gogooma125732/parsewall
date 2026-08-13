"""Scanner orchestration that preserves verified source snapshots through parsing."""

from dataclasses import dataclass, field
from pathlib import Path

from .contract import RiskLevel, ScanResult
from .derivative import (
    Publication,
    _publish_result,
    close_publication,
    destination_available,
)
from .limits import ScanLimits
from .parsers.html import scan_html
from .parsers.text import scan_text
from .policy import PolicyDecision, failure_finding, failure_kind_for_exception
from .preflight import VerifiedSource, verify_source


@dataclass(frozen=True, slots=True)
class ScanArtifacts:
    """A bounded result and the only conditionally releasable output path."""

    result: ScanResult
    derivative_path: Path | None
    _publication: Publication | None = field(default=None, repr=False, compare=False)

    def __del__(self) -> None:
        close_publication(self._publication)


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
    return result, output.visible_text if result.risk_level is RiskLevel.LOW else None


def scan_file(source: Path, output_dir: Path, limits: ScanLimits) -> ScanArtifacts:
    """Scan one source and publish only a safe, marker-prefixed low-risk derivative."""
    visible_text: str | None = None
    if not destination_available(output_dir):
        return ScanArtifacts(_failed_result(ValueError("output unavailable")), None)
    try:
        with verify_source(source, limits) as verified:
            result, visible_text = _scan_verified(verified, limits, source.suffix.casefold())
    except Exception as error:  # noqa: BLE001 -- scanner boundary must fail closed.
        result = _failed_result(error)
        visible_text = None

    try:
        publication = _publish_result(output_dir, result, visible_text)
    except Exception as error:  # noqa: BLE001 -- a failed release must not remain low.
        failure = _failed_result(error)
        try:
            publication = _publish_result(output_dir, failure, None)
        except Exception:  # noqa: BLE001 -- a broken recovery path remains fail-closed.
            return ScanArtifacts(failure, None)
        return ScanArtifacts(failure, None, publication)
    return ScanArtifacts(result, publication.derivative_path, publication)
