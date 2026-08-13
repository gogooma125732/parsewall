"""Closed, public result types for document scans."""

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

LOCATION_PATTERN = (
    r"^(?:"
    r"pdf:page=[1-9][0-9]{0,5}:object=[1-9][0-9]{0,8}"
    r"|docx:part=[A-Za-z0-9._-]{1,96}(?::paragraph=[1-9][0-9]{0,6})?"
    r"|pptx:slide=[1-9][0-9]{0,5}:shape=[1-9][0-9]{0,8}"
    r"|xlsx:sheet=[1-9][0-9]{0,5}:row=[1-9][0-9]{0,6}:column=[1-9][0-9]{0,5}"
    r"|html:node=[1-9][0-9]{0,8}"
    r"|text:line=[1-9][0-9]{0,8}"
    r"|image:region=[1-9][0-9]{0,8}"
    r"|file:metadata"
    r")$"
)


class RiskLevel(StrEnum):
    LOW = "low"
    REVIEW = "review"
    QUARANTINE = "quarantine"


class EvidenceCode(StrEnum):
    HIDDEN_INSTRUCTION_PATTERN = "HIDDEN_INSTRUCTION_PATTERN"
    VISIBLE_INSTRUCTION_PATTERN = "VISIBLE_INSTRUCTION_PATTERN"
    VISIBLE_EXTRACTED_TEXT_MISMATCH = "VISIBLE_EXTRACTED_TEXT_MISMATCH"
    ACTIVE_CONTENT_PRESENT = "ACTIVE_CONTENT_PRESENT"
    EXTERNAL_REFERENCE_PRESENT = "EXTERNAL_REFERENCE_PRESENT"
    ENCODED_INSTRUCTION_PATTERN = "ENCODED_INSTRUCTION_PATTERN"
    METADATA_INSTRUCTION_PATTERN = "METADATA_INSTRUCTION_PATTERN"
    UNSUPPORTED_FORMAT = "UNSUPPORTED_FORMAT"
    ENCRYPTED_DOCUMENT = "ENCRYPTED_DOCUMENT"
    CORRUPT_DOCUMENT = "CORRUPT_DOCUMENT"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    SCANNER_DEPENDENCY_UNAVAILABLE = "SCANNER_DEPENDENCY_UNAVAILABLE"
    RESULT_INTEGRITY_FAILURE = "RESULT_INTEGRITY_FAILURE"
    PARSER_FAILURE = "PARSER_FAILURE"


class AnomalyCode(StrEnum):
    WHITE_ON_WHITE_TEXT = "WHITE_ON_WHITE_TEXT"
    TRANSPARENT_TEXT = "TRANSPARENT_TEXT"
    OFF_CANVAS_TEXT = "OFF_CANVAS_TEXT"
    TINY_TEXT = "TINY_TEXT"
    HIDDEN_XML_TEXT = "HIDDEN_XML_TEXT"
    HIDDEN_SLIDE = "HIDDEN_SLIDE"
    SPEAKER_NOTES = "SPEAKER_NOTES"
    HIDDEN_SHEET = "HIDDEN_SHEET"
    HIDDEN_ROW = "HIDDEN_ROW"
    HIDDEN_COLUMN = "HIDDEN_COLUMN"
    DOM_HIDDEN_CONTENT = "DOM_HIDDEN_CONTENT"
    ZERO_WIDTH_CHARACTERS = "ZERO_WIDTH_CHARACTERS"
    BIDI_CONTROL_CHARACTERS = "BIDI_CONTROL_CHARACTERS"
    LONG_ENCODED_BLOCK = "LONG_ENCODED_BLOCK"
    OCR_TEXT_LAYER_MISMATCH = "OCR_TEXT_LAYER_MISMATCH"
    SCRIPT_CONTENT = "SCRIPT_CONTENT"
    MACRO_CONTENT = "MACRO_CONTENT"
    EXTERNAL_RELATIONSHIP = "EXTERNAL_RELATIONSHIP"


RISK_ORDER = {
    RiskLevel.LOW: 0,
    RiskLevel.REVIEW: 1,
    RiskLevel.QUARANTINE: 2,
}


@dataclass(frozen=True, slots=True)
class Finding:
    risk_level: RiskLevel
    evidence: EvidenceCode
    location: str
    anomaly: AnomalyCode | None = None


class ScanResult(BaseModel):
    """The bounded result that is safe to expose outside the scanner."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    risk_level: RiskLevel
    evidence: tuple[EvidenceCode, ...] = ()
    location: tuple[Annotated[str, StringConstraints(pattern=LOCATION_PATTERN)], ...] = ()
    structural_anomalies: tuple[AnomalyCode, ...] = ()

    @classmethod
    def from_findings(cls, findings: Iterable[Finding]) -> "ScanResult":
        items = tuple(findings)
        risk = max(
            (item.risk_level for item in items),
            default=RiskLevel.LOW,
            key=lambda value: RISK_ORDER[value],
        )
        return cls(
            risk_level=risk,
            evidence=tuple(sorted({item.evidence for item in items}, key=str)),
            location=tuple(sorted({item.location for item in items})),
            structural_anomalies=tuple(
                sorted(
                    {item.anomaly for item in items if item.anomaly is not None},
                    key=str,
                )
            ),
        )

    def to_public_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")
