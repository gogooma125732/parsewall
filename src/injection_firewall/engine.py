"""Scanner orchestration that preserves verified source snapshots through parsing."""

from dataclasses import dataclass
from pathlib import Path

from .contract import RiskLevel, ScanResult
from .derivative import publish_result
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


def _reject_output_aliases(source: Path, output_dir: Path) -> None:
    """Reject source/output collisions before any scanner output is opened."""
    if output_dir.exists() and output_dir.is_symlink():
        raise ValueError("output unavailable")
    for slot in (output_dir / "result.json", output_dir / "visible.txt"):
        try:
            if source.samefile(slot):
                raise ValueError("output unavailable")
        except FileNotFoundError:
            continue


def scan_file(source: Path, output_dir: Path, limits: ScanLimits) -> ScanArtifacts:
    """Scan one source and publish only a safe, marker-prefixed low-risk derivative."""
    visible_text: str | None = None
    try:
        _reject_output_aliases(source, output_dir)
        with verify_source(source, limits) as verified:
            result, visible_text = _scan_verified(verified, limits, source.suffix.casefold())
    except Exception as error:  # noqa: BLE001 -- scanner boundary must fail closed.
        result = _failed_result(error)
        visible_text = None

    try:
        derivative_path = publish_result(output_dir, result, visible_text)
    except Exception as error:  # noqa: BLE001 -- a failed release must not remain low.
        failure = _failed_result(error)
        try:
            publish_result(output_dir, failure, None)
        except Exception:  # noqa: BLE001, S110 -- a broken recovery path remains fail-closed.
            pass
        return ScanArtifacts(failure, None)
    return ScanArtifacts(result, derivative_path)
