import zipfile
from pathlib import Path

import pytest

from injection_firewall.limits import ScanLimits
from injection_firewall.ooxml import BoundedZip, ContainerViolation
from injection_firewall.preflight import verify_source


def write_zip(path: Path, members: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, contents in members.items():
            archive.writestr(name, contents)
    return path


def content_types(main_part: str, content_type: str) -> bytes:
    return (
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f'<Override PartName="/{main_part}" ContentType="{content_type}"/>'
        "</Types>"
    ).encode()


def test_bounded_zip_rejects_parent_member(tmp_path: Path) -> None:
    source = write_zip(
        tmp_path / "bad.docx",
        {
            "[Content_Types].xml": content_types(
                "word/document.xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            ),
            "word/document.xml": b"<w/>",
            "../escape": b"x",
        },
    )
    with verify_source(source, ScanLimits()) as verified:
        assert verified.report.findings


def test_bounded_zip_reads_only_registered_members(tmp_path: Path) -> None:
    source = write_zip(
        tmp_path / "ok.docx",
        {
            "[Content_Types].xml": content_types(
                "word/document.xml",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            ),
            "word/document.xml": b"<document/>",
        },
    )
    with verify_source(source, ScanLimits()) as verified, BoundedZip(verified, ScanLimits()) as package:
        assert package.read_member("word/document.xml") == b"<document/>"
        with pytest.raises(ContainerViolation):
            package.read_member("missing.xml")
