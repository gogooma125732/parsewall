import subprocess

import pytest

from injection_firewall.contract import (
    AnomalyCode,
    EvidenceCode,
    Finding,
    RiskLevel,
)
from injection_firewall.policy import (
    FailureKind,
    PolicyDecision,
    ResultIntegrityError,
    failure_finding,
    failure_kind_for_exception,
)


def test_missing_required_check_is_quarantined():
    decision = PolicyDecision((), frozenset({"ocr", "structure"}), frozenset({"structure"}))
    result = decision.result()
    assert result.risk_level is RiskLevel.QUARANTINE
    assert result.evidence == (EvidenceCode.SCANNER_DEPENDENCY_UNAVAILABLE,)
    assert result.location == ("file:structure",)


def test_optional_classifier_cannot_lower_deterministic_risk():
    base = Finding(
        RiskLevel.QUARANTINE,
        EvidenceCode.ACTIVE_CONTENT_PRESENT,
        "html:node=2",
        AnomalyCode.SCRIPT_CONTENT,
    )
    decision = PolicyDecision((base,), frozenset(), frozenset())
    assert decision.with_classifier_risk(RiskLevel.LOW).result().risk_level is RiskLevel.QUARANTINE


@pytest.mark.parametrize(
    ("kind", "evidence"),
    [
        (FailureKind.PARSER, EvidenceCode.PARSER_FAILURE),
        (FailureKind.DEPENDENCY, EvidenceCode.SCANNER_DEPENDENCY_UNAVAILABLE),
        (FailureKind.TIMEOUT, EvidenceCode.RESOURCE_LIMIT_EXCEEDED),
        (FailureKind.RESOURCE_LIMIT, EvidenceCode.RESOURCE_LIMIT_EXCEEDED),
        (FailureKind.RESULT_INTEGRITY, EvidenceCode.RESULT_INTEGRITY_FAILURE),
        (FailureKind.UNKNOWN, EvidenceCode.PARSER_FAILURE),
    ],
)
def test_failure_finding_uses_closed_quarantine_evidence(kind, evidence):
    finding = failure_finding(kind, "file:structure")
    assert finding.risk_level is RiskLevel.QUARANTINE
    assert finding.evidence is evidence
    assert finding.location == "file:structure"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError("document text"), FailureKind.TIMEOUT),
        (subprocess.TimeoutExpired(["scanner"], 1), FailureKind.TIMEOUT),
        (MemoryError("document text"), FailureKind.RESOURCE_LIMIT),
        (FileNotFoundError("scanner path"), FailureKind.DEPENDENCY),
        (ValueError("malformed container"), FailureKind.PARSER),
        (ResultIntegrityError("invalid worker result"), FailureKind.RESULT_INTEGRITY),
        (RuntimeError("untrusted document"), FailureKind.UNKNOWN),
    ],
)
def test_exception_mapping_is_closed_and_never_uses_exception_text(error, expected):
    finding = failure_finding(failure_kind_for_exception(error), "file:structure")
    public_result = PolicyDecision((finding,), frozenset(), frozenset()).result().to_public_dict()
    assert failure_kind_for_exception(error) is expected
    assert str(error) not in str(public_result)
