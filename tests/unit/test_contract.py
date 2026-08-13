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
