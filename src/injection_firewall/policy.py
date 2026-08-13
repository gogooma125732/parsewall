"""Fail-closed aggregation and sanitized scanner-failure mapping."""

import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, replace
from enum import StrEnum
from re import fullmatch

from .contract import LOCATION_PATTERN, EvidenceCode, Finding, RiskLevel, ScanResult


class FailureKind(StrEnum):
    """Closed categories for scanner boundary failures."""

    PARSER = "parser"
    DEPENDENCY = "dependency"
    TIMEOUT = "timeout"
    RESOURCE_LIMIT = "resource_limit"
    RESULT_INTEGRITY = "result_integrity"
    UNKNOWN = "unknown"


FAILURE_EVIDENCE = {
    FailureKind.PARSER: EvidenceCode.PARSER_FAILURE,
    FailureKind.DEPENDENCY: EvidenceCode.SCANNER_DEPENDENCY_UNAVAILABLE,
    FailureKind.TIMEOUT: EvidenceCode.RESOURCE_LIMIT_EXCEEDED,
    FailureKind.RESOURCE_LIMIT: EvidenceCode.RESOURCE_LIMIT_EXCEEDED,
    FailureKind.RESULT_INTEGRITY: EvidenceCode.RESULT_INTEGRITY_FAILURE,
    FailureKind.UNKNOWN: EvidenceCode.PARSER_FAILURE,
}


class ResultIntegrityError(Exception):
    """A scanner result failed its internal integrity validation."""


def failure_kind_for_exception(error: BaseException) -> FailureKind:
    """Classify scanner failures without propagating untrusted exception details."""
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        return FailureKind.TIMEOUT
    if isinstance(error, MemoryError):
        return FailureKind.RESOURCE_LIMIT
    if isinstance(error, FileNotFoundError):
        return FailureKind.DEPENDENCY
    if isinstance(error, ResultIntegrityError):
        return FailureKind.RESULT_INTEGRITY
    if isinstance(error, (zipfile.BadZipFile, tarfile.TarError, EOFError, UnicodeDecodeError, ValueError)):
        return FailureKind.PARSER
    return FailureKind.UNKNOWN


def failure_finding(kind: FailureKind, location: str = "file:structure") -> Finding:
    """Create an opaque, fail-closed finding for an internal scanner failure."""
    safe_location = (
        location
        if isinstance(location, str) and fullmatch(LOCATION_PATTERN, location)
        else "file:structure"
    )
    return Finding(
        RiskLevel.QUARANTINE,
        FAILURE_EVIDENCE[kind],
        safe_location,
    )


@dataclass(frozen=True)
class PolicyDecision:
    """Combines deterministic findings without allowing later stages to lower risk."""

    findings: tuple[Finding, ...]
    required_checks: frozenset[str]
    completed_checks: frozenset[str]
    classifier_risk: RiskLevel | None = None

    def with_classifier_risk(self, risk: RiskLevel) -> "PolicyDecision":
        return replace(self, classifier_risk=risk)

    def result(self) -> ScanResult:
        findings = list(self.findings)
        if not self.required_checks.issubset(self.completed_checks):
            findings.append(failure_finding(FailureKind.DEPENDENCY))
        result = ScanResult.from_findings(findings)
        if self.classifier_risk is None:
            return result
        return result.raise_to(self.classifier_risk)
