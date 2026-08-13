import hashlib
import zipfile
from pathlib import Path

import pytest

from injection_firewall.contract import EvidenceCode, RiskLevel
from injection_firewall.limits import ScanLimits
from injection_firewall.preflight import DocumentFormat, inspect_source


def risk_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 0,
        RiskLevel.REVIEW: 1,
        RiskLevel.QUARANTINE: 2,
    }[level]


def test_extension_magic_mismatch_is_quarantined(tmp_path: Path):
    source = tmp_path / "report.pdf"
    source.write_text("plain text", encoding="utf-8")

    report = inspect_source(source, ScanLimits())

    assert EvidenceCode.CORRUPT_DOCUMENT in {finding.evidence for finding in report.findings}
    assert max((finding.risk_level for finding in report.findings), key=risk_rank) is RiskLevel.QUARANTINE


def test_input_over_limit_is_rejected_without_reading_past_limit(tmp_path: Path):
    source = tmp_path / "large.txt"
    source.write_bytes(b"x" * 33)

    report = inspect_source(source, ScanLimits(max_upload_bytes=32))

    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED
    assert report.sha256 == ""
    assert report.size == 33


def test_input_at_size_limit_is_hashed_and_detected_as_text(tmp_path: Path):
    source = tmp_path / "boundary.txt"
    payload = b"x" * 32
    source.write_bytes(payload)

    report = inspect_source(source, ScanLimits(max_upload_bytes=32))

    assert report.format is DocumentFormat.TEXT
    assert report.sha256 == hashlib.sha256(payload).hexdigest()
    assert report.size == 32
    assert report.findings == ()


@pytest.mark.parametrize("stem", ["a", "space name", "\u2603", "..hidden"])
def test_preflight_finding_never_includes_source_filename(tmp_path: Path, stem: str):
    source = tmp_path / f"{stem}.pdf"
    source.write_bytes(b"not a PDF")

    report = inspect_source(source, ScanLimits())

    assert EvidenceCode.CORRUPT_DOCUMENT in {finding.evidence for finding in report.findings}
    assert source.name not in repr(report)
    assert str(source) not in repr(report)


def test_invalid_utf8_text_is_not_accepted_as_text(tmp_path: Path):
    source = tmp_path / "invalid.txt"
    source.write_bytes(b"\xff\xfe\xff")

    report = inspect_source(source, ScanLimits())

    assert report.format is DocumentFormat.UNKNOWN
    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT
    assert report.findings[0].risk_level is RiskLevel.QUARANTINE


def test_docx_subtype_is_identified_from_bounded_content_types_metadata(tmp_path: Path):
    source = tmp_path / "report.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            b'<Types><Override ContentType="application/vnd.openxmlformats-'
            b'officedocument.wordprocessingml.document.main+xml"/></Types>',
        )
        archive.writestr("word/document.xml", b"<document/>")

    report = inspect_source(source, ScanLimits(max_container_members=2))

    assert report.format is DocumentFormat.DOCX
    assert report.findings == ()


def test_ooxml_metadata_member_is_bounded_before_reading(tmp_path: Path):
    source = tmp_path / "too-large.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", b"x" * 17)

    report = inspect_source(source, ScanLimits(max_container_member_bytes=16))

    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED
    assert report.findings[0].location == "file:structure"


def test_container_member_limit_is_enforced_from_zip_metadata(tmp_path: Path):
    source = tmp_path / "many.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("word/document.xml", b"<document/>")

    report = inspect_source(source, ScanLimits(max_container_members=1))

    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED
