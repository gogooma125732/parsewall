import pytest
from pydantic import ValidationError

from injection_firewall.contract import (
    AnomalyCode,
    EvidenceCode,
    Finding,
    RiskLevel,
    ScanResult,
)


def test_public_result_has_exactly_four_keys_and_sorted_unique_arrays():
    result = ScanResult.from_findings([
        Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_INSTRUCTION_PATTERN,
                "text:line=9", AnomalyCode.ZERO_WIDTH_CHARACTERS),
        Finding(RiskLevel.REVIEW, EvidenceCode.VISIBLE_INSTRUCTION_PATTERN,
                "text:line=9", AnomalyCode.ZERO_WIDTH_CHARACTERS),
    ])
    assert result.to_public_dict() == {
        "risk_level": "review",
        "evidence": ["VISIBLE_INSTRUCTION_PATTERN"],
        "location": ["text:line=9"],
        "structural_anomalies": ["ZERO_WIDTH_CHARACTERS"],
    }


def test_result_rejects_extra_fields_and_unbounded_location():
    with pytest.raises(ValidationError):
        ScanResult.model_validate({
            "risk_level": "low", "evidence": [], "location": ["../../secret"],
            "structural_anomalies": [], "extra": "forbidden",
        })


def test_result_accepts_the_coarse_structure_location():
    result = ScanResult.from_findings([
        Finding(RiskLevel.QUARANTINE, EvidenceCode.PARSER_FAILURE, "file:structure"),
    ])
    assert result.location == ("file:structure",)


@pytest.mark.parametrize(
    ("evidence", "minimum_risk"),
    [
        (EvidenceCode.PARSER_FAILURE, RiskLevel.QUARANTINE),
        (EvidenceCode.SCANNER_DEPENDENCY_UNAVAILABLE, RiskLevel.REVIEW),
        (EvidenceCode.RESOURCE_LIMIT_EXCEEDED, RiskLevel.QUARANTINE),
    ],
)
def test_direct_result_rejects_failure_evidence_below_minimum_risk(
    evidence: EvidenceCode, minimum_risk: RiskLevel
):
    with pytest.raises(ValidationError):
        ScanResult(
            risk_level=RiskLevel.LOW,
            evidence=(evidence,),
            location=("file:metadata",),
        )


@pytest.mark.parametrize(
    ("evidence", "minimum_risk"),
    [
        (EvidenceCode.PARSER_FAILURE, RiskLevel.QUARANTINE),
        (EvidenceCode.SCANNER_DEPENDENCY_UNAVAILABLE, RiskLevel.REVIEW),
        (EvidenceCode.RESOURCE_LIMIT_EXCEEDED, RiskLevel.QUARANTINE),
    ],
)
def test_from_findings_raises_failure_evidence_to_minimum_risk(
    evidence: EvidenceCode, minimum_risk: RiskLevel
):
    result = ScanResult.from_findings([
        Finding(RiskLevel.LOW, evidence, "file:metadata"),
    ])
    assert result.risk_level is minimum_risk


def test_from_findings_selects_most_restrictive_caller_risk():
    result = ScanResult.from_findings([
        Finding(RiskLevel.LOW, EvidenceCode.METADATA_INSTRUCTION_PATTERN, "file:metadata"),
        Finding(RiskLevel.QUARANTINE, EvidenceCode.VISIBLE_INSTRUCTION_PATTERN, "text:line=4"),
    ])
    assert result.risk_level is RiskLevel.QUARANTINE


def test_finding_rejects_invalid_runtime_values_and_is_immutable():
    with pytest.raises(ValidationError):
        Finding("invalid", EvidenceCode.VISIBLE_INSTRUCTION_PATTERN, "text:line=4")

    finding = Finding(RiskLevel.LOW, EvidenceCode.VISIBLE_INSTRUCTION_PATTERN, "text:line=4")
    with pytest.raises(ValidationError):
        finding.risk_level = RiskLevel.REVIEW
