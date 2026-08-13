import hashlib
import os
import struct
import zipfile
from pathlib import Path
from typing import BinaryIO

import pytest

from injection_firewall.contract import EvidenceCode, RiskLevel
from injection_firewall.limits import ScanLimits
from injection_firewall.preflight import DocumentFormat, inspect_source, verify_source

WORD_TYPES = (
    b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    b'<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
    b'officedocument.wordprocessingml.document.main+xml"/>'
    b"</Types>"
)


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
            WORD_TYPES,
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


def write_docx(source: Path, content_types: bytes, *members: tuple[str, bytes]) -> None:
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", content_types)
        for name, contents in members:
            archive.writestr(name, contents)


def test_symlink_is_rejected_without_following_target(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_text("safe", encoding="utf-8")
    source = tmp_path / "link.txt"
    source.symlink_to(target)

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_non_regular_source_is_rejected(tmp_path: Path):
    report = inspect_source(tmp_path, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_path_substitution_before_open_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "source.txt"
    target = tmp_path / "target.txt"
    source.write_text("safe", encoding="utf-8")
    target.write_text("attacker", encoding="utf-8")
    original_open = os.open

    def substitute_then_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int) -> int:
        if Path(path) == source:
            os.replace(target, source)
        return original_open(path, flags)

    monkeypatch.setattr("injection_firewall.preflight.os.open", substitute_then_open)

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].risk_level is RiskLevel.QUARANTINE


def test_source_growth_during_copy_returns_no_partial_hash(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "growth.txt"
    source.write_bytes(b"x" * 32)
    original_read = os.read
    calls = 0

    def grow_after_read(fd: int, size: int) -> bytes:
        nonlocal calls
        result = original_read(fd, size)
        calls += 1
        if calls == 1:
            with source.open("ab") as writer:
                writer.write(b"y")
        return result

    monkeypatch.setattr("injection_firewall.preflight.os.read", grow_after_read)

    report = inspect_source(source, ScanLimits(max_upload_bytes=64))

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_verified_source_parser_reads_the_immutable_snapshot(tmp_path: Path):
    source = tmp_path / "snapshot.txt"
    source.write_text("original", encoding="utf-8")

    with verify_source(source, ScanLimits()) as verified:
        source.write_text("changed!", encoding="utf-8")
        with verified.open() as snapshot:
            assert snapshot.read() == b"original"
        assert verified.report.sha256 == hashlib.sha256(b"original").hexdigest()


def test_verified_source_readers_are_read_only_and_independent(tmp_path: Path):
    source = tmp_path / "readers.txt"
    source.write_text("original", encoding="utf-8")

    with verify_source(source, ScanLimits()) as verified, verified.open() as first, verified.open() as second:
        assert first.read(1) == b"o"
        assert second.read(1) == b"o"
        with pytest.raises(OSError):
            os.write(first.fileno(), b"!")


def test_ordinary_oversized_zip_member_is_rejected(tmp_path: Path):
    source = tmp_path / "oversized.docx"
    write_docx(source, WORD_TYPES, ("word/document.xml", b"x" * 17))

    report = inspect_source(source, ScanLimits(max_container_member_bytes=16))

    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_zip_total_size_and_depth_are_rejected_from_metadata(tmp_path: Path):
    total = tmp_path / "total.docx"
    deep = tmp_path / "deep.docx"
    write_docx(total, WORD_TYPES, ("word/document.xml", b"x" * 17))
    write_docx(deep, WORD_TYPES, ("a/b/c/document.xml", b"x"))

    total_report = inspect_source(total, ScanLimits(max_container_uncompressed_bytes=16))
    deep_report = inspect_source(deep, ScanLimits(max_container_depth=2))

    assert total_report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED
    assert deep_report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_zip_time_limit_is_closed_before_container_parser(tmp_path: Path):
    source = tmp_path / "timeout.docx"
    write_docx(source, WORD_TYPES, ("word/document.xml", b"x"))

    report = inspect_source(source, ScanLimits(max_seconds=1e-12))

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_declared_central_directory_over_limit_is_rejected_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "directory.docx"
    write_docx(source, WORD_TYPES, ("word/document.xml", b"x"))
    contents = bytearray(source.read_bytes())
    eocd = contents.rfind(b"PK\x05\x06")
    struct.pack_into("<L", contents, eocd + 12, 4097)
    source.write_bytes(contents)

    def must_not_construct_zipfile(*_: object, **__: object) -> None:
        raise AssertionError("central-directory limit must run before ZipFile")

    monkeypatch.setattr("injection_firewall.preflight.zipfile.ZipFile", must_not_construct_zipfile)

    report = inspect_source(source, ScanLimits(max_container_directory_bytes=4096))

    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


@pytest.mark.parametrize("unsafe_name", ["../word/document.xml", "/word/document.xml"])
def test_unsafe_zip_member_name_is_rejected(tmp_path: Path, unsafe_name: str):
    source = tmp_path / "unsafe.docx"
    write_docx(source, WORD_TYPES, (unsafe_name, b"x"), ("word/document.xml", b"x"))

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_symlink_zip_member_is_rejected(tmp_path: Path):
    source = tmp_path / "symlink.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", WORD_TYPES)
        member = zipfile.ZipInfo("word/document.xml")
        member.create_system = 3
        member.external_attr = (0o120777 << 16)
        archive.writestr(member, b"target")

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_duplicate_canonical_zip_member_is_rejected(tmp_path: Path):
    source = tmp_path / "duplicate.docx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("[Content_Types].xml", WORD_TYPES)
        archive.writestr("word/document.xml", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("word/document.xml", b"second")

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_ooxml_content_type_in_comment_is_not_classified_as_docx(tmp_path: Path):
    source = tmp_path / "comment.docx"
    write_docx(
        source,
        b'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        b"<!-- wordprocessingml.document.main+xml -->"
        b"</Types>",
    )

    report = inspect_source(source, ScanLimits())

    assert report.format is DocumentFormat.ZIP
    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_declared_ooxml_main_part_must_exist(tmp_path: Path):
    source = tmp_path / "missing-main.docx"
    write_docx(source, WORD_TYPES)

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_ooxml_main_part_cannot_be_a_directory_entry(tmp_path: Path):
    source = tmp_path / "directory-main.docx"
    write_docx(source, WORD_TYPES, ("word/document.xml/", b""))

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


@pytest.mark.parametrize(
    "content_types",
    [
        WORD_TYPES.replace(b"<Types ", b'<Types unexpected="attribute" ', 1),
        WORD_TYPES.replace(b"/>", b"><unexpected/></Override>", 1),
        WORD_TYPES.replace(b"/>", b">text</Override>", 1),
    ],
)
def test_ooxml_content_types_rejects_noncanonical_structure(tmp_path: Path, content_types: bytes):
    source = tmp_path / "noncanonical.docx"
    write_docx(source, content_types, ("word/document.xml", b"<document/>"))

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


@pytest.mark.parametrize("unsafe_name", ["C:/word/document.xml", "C:\\word\\document.xml", "\\\\host\\share\\document.xml"])
def test_drive_and_unc_qualified_zip_member_name_is_rejected(tmp_path: Path, unsafe_name: str):
    source = tmp_path / "drive.docx"
    write_docx(source, WORD_TYPES, (unsafe_name, b"x"), ("word/document.xml", b"x"))

    report = inspect_source(source, ScanLimits())

    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_same_size_source_mutation_during_copy_returns_no_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "mutation.txt"
    source.write_bytes(b"x" * 32)
    original_read = os.read
    calls = 0

    def mutate_after_read(fd: int, size: int) -> bytes:
        nonlocal calls
        result = original_read(fd, size)
        calls += 1
        if calls == 1:
            with source.open("r+b") as writer:
                writer.write(b"y" * 32)
        return result

    monkeypatch.setattr("injection_firewall.preflight.os.read", mutate_after_read)

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_short_read_before_declared_size_returns_no_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "short.txt"
    source.write_bytes(b"x" * 32)
    monkeypatch.setattr("injection_firewall.preflight.os.read", lambda _fd, _size: b"")

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].evidence is EvidenceCode.CORRUPT_DOCUMENT


def test_timeout_inside_central_directory_loop_closes_before_zipfile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source = tmp_path / "record-timeout.docx"
    write_docx(source, WORD_TYPES, ("word/document.xml", b"<document/>"))
    seen_eocd = False
    original_find_eocd = __import__("injection_firewall.preflight", fromlist=["_find_eocd"])._find_eocd

    def record_eocd(*args: object) -> tuple[int, int, int, int]:
        nonlocal seen_eocd
        result = original_find_eocd(*args)
        seen_eocd = True
        return result

    def monotonic() -> float:
        return 2.0 if seen_eocd else 0.0

    def must_not_construct_zipfile(*_: object, **__: object) -> None:
        raise AssertionError("record-loop timeout must run before ZipFile")

    monkeypatch.setattr("injection_firewall.preflight._find_eocd", record_eocd)
    monkeypatch.setattr("injection_firewall.preflight.time.monotonic", monotonic)
    monkeypatch.setattr("injection_firewall.preflight.zipfile.ZipFile", must_not_construct_zipfile)

    report = inspect_source(source, ScanLimits(max_seconds=1.0))

    assert seen_eocd
    assert report.findings[0].evidence is EvidenceCode.RESOURCE_LIMIT_EXCEEDED


def test_snapshot_mkstemp_failure_is_sanitized(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "mkstemp.txt"
    source.write_text("safe", encoding="utf-8")

    def fail_mkstemp() -> tuple[int, str]:
        raise OSError("document path must not leak")

    monkeypatch.setattr("injection_firewall.preflight.tempfile.mkstemp", fail_mkstemp)

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].risk_level is RiskLevel.QUARANTINE
    assert "document path" not in repr(report)


def test_snapshot_fdopen_failure_closes_and_unlinks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    source = tmp_path / "fdopen.txt"
    source.write_text("safe", encoding="utf-8")
    snapshot_path = tmp_path / "failed-snapshot"
    descriptor = os.open(snapshot_path, os.O_CREAT | os.O_RDWR, 0o600)

    monkeypatch.setattr(
        "injection_firewall.preflight.tempfile.mkstemp", lambda: (descriptor, str(snapshot_path))
    )

    def fail_fdopen(*_: object, **__: object) -> BinaryIO:
        raise OSError("snapshot setup failed")

    monkeypatch.setattr("injection_firewall.preflight.os.fdopen", fail_fdopen)

    report = inspect_source(source, ScanLimits())

    assert report.sha256 == ""
    assert report.findings[0].risk_level is RiskLevel.QUARANTINE
    assert not snapshot_path.exists()
    with pytest.raises(OSError):
        os.fstat(descriptor)
