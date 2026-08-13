"""Bounded, immutable source preparation before document parsing."""

import codecs
import errno
import hashlib
import os
import stat
import struct
import tempfile
import time
import zipfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Self

from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]
from defusedxml.ElementTree import (  # type: ignore[import-untyped]
    ParseError,
    fromstring,
)

from .contract import EvidenceCode, Finding, RiskLevel
from .limits import ScanLimits
from .policy import failure_finding, failure_kind_for_exception

_HEAD_BYTES = 8192
_HASH_CHUNK_BYTES = 1024 * 1024
_EOCD_SIGNATURE = b"PK\x05\x06"
_CENTRAL_SIGNATURE = b"PK\x01\x02"
_EOCD_SIZE = 22
_MAX_ZIP_COMMENT_BYTES = 65_535
_CENTRAL_FIXED_SIZE = 46
_CONTENT_TYPES_PART = "[Content_Types].xml"
_CONTENT_TYPES_NAMESPACE = "http://schemas.openxmlformats.org/package/2006/content-types"
_TYPES_TAG = f"{{{_CONTENT_TYPES_NAMESPACE}}}Types"
_DEFAULT_TAG = f"{{{_CONTENT_TYPES_NAMESPACE}}}Default"
_OVERRIDE_TAG = f"{{{_CONTENT_TYPES_NAMESPACE}}}Override"


class DocumentFormat(StrEnum):
    """Formats recognized by the bounded preflight stage."""

    UNKNOWN = "unknown"
    TEXT = "text"
    PDF = "pdf"
    ZIP = "zip"
    DOCX = "docx"
    PPTX = "pptx"
    XLSX = "xlsx"
    PNG = "png"
    JPEG = "jpeg"


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """Opaque input facts and coarse findings for the next scanner stage."""

    format: DocumentFormat
    sha256: str
    size: int
    findings: tuple[Finding, ...]


@dataclass(frozen=True, slots=True)
class _CentralMember:
    name: str
    uncompressed_size: int
    external_attributes: int
    is_directory: bool


class _CorruptContainer(Exception):
    """ZIP metadata was malformed or unsafe."""


class _ContainerLimit(Exception):
    """ZIP metadata exceeded a configured resource limit."""


@dataclass(slots=True)
class VerifiedSource:
    """A job-scoped, immutable snapshot that later parsers can safely read."""

    report: PreflightReport
    _snapshot_path: Path | None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._snapshot_path is not None:
            try:
                self._snapshot_path.unlink()
            except FileNotFoundError:
                pass
            self._snapshot_path = None

    def open(self) -> BinaryIO:
        """Open an independent reader for the validated immutable bytes."""
        if self._snapshot_path is None or self.report.findings:
            raise ValueError("no usable verified source is available")
        return self._snapshot_path.open("rb")


def _quarantine_finding(evidence: EvidenceCode) -> Finding:
    return Finding(RiskLevel.QUARANTINE, evidence, "file:structure")


def _failed_report(evidence: EvidenceCode, *, size: int = 0) -> PreflightReport:
    """Return a failure report without a partial or unverified digest."""
    return PreflightReport(
        DocumentFormat.UNKNOWN,
        "",
        size,
        (_quarantine_finding(evidence),),
    )


def _failure_report(error: BaseException, *, size: int = 0) -> PreflightReport:
    return PreflightReport(
        DocumentFormat.UNKNOWN,
        "",
        size,
        (failure_finding(failure_kind_for_exception(error)),),
    )


def _within_time_limit(started: float, limits: ScanLimits) -> bool:
    return time.monotonic() - started <= limits.max_seconds


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _open_without_following(path: Path) -> int:
    flags = os.O_RDONLY
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        try:
            return os.open(path, flags | nofollow)
        except OSError as error:
            if error.errno != errno.EINVAL:
                raise
    return os.open(path, flags)


def _fixed_signature(head: bytes) -> DocumentFormat:
    if head.startswith(b"%PDF-"):
        return DocumentFormat.PDF
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return DocumentFormat.PNG
    if head.startswith(b"\xff\xd8\xff"):
        return DocumentFormat.JPEG
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return DocumentFormat.ZIP
    return DocumentFormat.UNKNOWN


def _text_decoder(head: bytes) -> codecs.IncrementalDecoder:
    if head.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return codecs.getincrementaldecoder("utf-16")("strict")
    if head.startswith(codecs.BOM_UTF8):
        return codecs.getincrementaldecoder("utf-8-sig")("strict")
    return codecs.getincrementaldecoder("utf-8")("strict")


def _member_depth(name: str) -> int:
    return len(name.split("/"))


def _canonical_member_name(name: str) -> tuple[str, bool]:
    if (
        not name
        or name.startswith(("/", "\\"))
        or "\\" in name
        or "\x00" in name
        or (len(name) >= 2 and name[0].isascii() and name[0].isalpha() and name[1] == ":")
    ):
        raise _CorruptContainer
    is_directory = name.endswith("/")
    candidate = name[:-1] if is_directory else name
    parts = candidate.split("/")
    if not candidate or any(part in {"", ".", ".."} for part in parts):
        raise _CorruptContainer
    return candidate, is_directory


def _read_exact(handle: BinaryIO, offset: int, size: int) -> bytes:
    handle.seek(offset)
    contents = handle.read(size)
    if len(contents) != size:
        raise _CorruptContainer
    return contents


def _find_eocd(handle: BinaryIO, size: int) -> tuple[int, int, int, int]:
    tail_size = min(size, _EOCD_SIZE + _MAX_ZIP_COMMENT_BYTES)
    tail_offset = size - tail_size
    tail = _read_exact(handle, tail_offset, tail_size)
    position = tail.rfind(_EOCD_SIGNATURE)
    while position >= 0:
        if len(tail) - position >= _EOCD_SIZE:
            fields = struct.unpack_from("<4s4H2LH", tail, position)
            _, disk, start_disk, disk_count, total_count, directory_size, directory_offset, comment_size = fields
            if position + _EOCD_SIZE + comment_size == len(tail):
                if disk != 0 or start_disk != 0 or disk_count != total_count:
                    raise _CorruptContainer
                if total_count == 0xFFFF or directory_size == 0xFFFFFFFF:
                    raise _ContainerLimit
                return total_count, directory_size, directory_offset, tail_offset + position
        position = tail.rfind(_EOCD_SIGNATURE, 0, position)
    raise _CorruptContainer


def _prescan_central_directory(
    handle: BinaryIO,
    size: int,
    limits: ScanLimits,
    started: float,
) -> tuple[_CentralMember, ...]:
    count, directory_size, directory_offset, eocd_offset = _find_eocd(handle, size)
    if count > limits.max_container_members or directory_size > limits.max_container_directory_bytes:
        raise _ContainerLimit
    if directory_offset + directory_size > eocd_offset:
        raise _CorruptContainer
    contents = _read_exact(handle, directory_offset, directory_size)
    cursor = 0
    total_uncompressed = 0
    members: list[_CentralMember] = []
    names: set[str] = set()
    for _ in range(count):
        if not _within_time_limit(started, limits):
            raise _ContainerLimit
        if cursor + _CENTRAL_FIXED_SIZE > len(contents):
            raise _CorruptContainer
        fields = struct.unpack_from("<4s6H3L5H2L", contents, cursor)
        (
            signature,
            _,
            _,
            flags,
            _,
            _,
            _,
            _,
            _,
            uncompressed_size,
            name_size,
            extra_size,
            comment_size,
            _,
            _,
            external_attributes,
            _,
        ) = fields
        if signature != _CENTRAL_SIGNATURE:
            raise _CorruptContainer
        cursor += _CENTRAL_FIXED_SIZE
        record_end = cursor + name_size + extra_size + comment_size
        if record_end > len(contents):
            raise _CorruptContainer
        encoded_name = contents[cursor : cursor + name_size]
        try:
            name = encoded_name.decode("utf-8" if flags & 0x800 else "cp437", "strict")
        except UnicodeDecodeError as error:
            raise _CorruptContainer from error
        canonical_name, is_directory = _canonical_member_name(name)
        unix_mode = external_attributes >> 16
        if stat.S_ISLNK(unix_mode) or canonical_name in names:
            raise _CorruptContainer
        if _member_depth(canonical_name) > limits.max_container_depth:
            raise _ContainerLimit
        if uncompressed_size > limits.max_container_member_bytes:
            raise _ContainerLimit
        total_uncompressed += uncompressed_size
        if total_uncompressed > limits.max_container_uncompressed_bytes:
            raise _ContainerLimit
        names.add(canonical_name)
        members.append(
            _CentralMember(canonical_name, uncompressed_size, external_attributes, is_directory)
        )
        cursor = record_end
    if cursor != len(contents):
        raise _CorruptContainer
    return tuple(members)


_OOXML_MAIN_CONTENT_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": DocumentFormat.DOCX,
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": DocumentFormat.PPTX,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": DocumentFormat.XLSX,
}


def _parse_content_types(contents: bytes, members: tuple[_CentralMember, ...]) -> DocumentFormat:
    try:
        root = fromstring(contents)
    except (DefusedXmlException, ParseError, UnicodeError) as error:
        raise _CorruptContainer from error
    if root.tag != _TYPES_TAG or root.attrib or not _is_whitespace(root.text):
        raise _CorruptContainer
    defaults: set[str] = set()
    overrides: dict[str, str] = {}
    for child in root:
        if list(child) or not _is_whitespace(child.text) or not _is_whitespace(child.tail):
            raise _CorruptContainer
        if child.tag == _DEFAULT_TAG:
            extension = child.get("Extension")
            content_type = child.get("ContentType")
            if (
                set(child.attrib) != {"Extension", "ContentType"}
                or not extension
                or not content_type
                or extension.lower() in defaults
            ):
                raise _CorruptContainer
            defaults.add(extension.lower())
        elif child.tag == _OVERRIDE_TAG:
            part_name = child.get("PartName")
            content_type = child.get("ContentType")
            if (
                set(child.attrib) != {"PartName", "ContentType"}
                or not part_name
                or not content_type
                or not part_name.startswith("/")
            ):
                raise _CorruptContainer
            canonical_name, is_directory = _canonical_member_name(part_name[1:])
            if is_directory:
                raise _CorruptContainer
            if canonical_name in overrides:
                raise _CorruptContainer
            overrides[canonical_name] = content_type
        else:
            raise _CorruptContainer
    member_names = {member.name for member in members if not member.is_directory}
    matching = [
        (name, _OOXML_MAIN_CONTENT_TYPES[content_type])
        for name, content_type in overrides.items()
        if content_type in _OOXML_MAIN_CONTENT_TYPES
    ]
    if len(matching) != 1:
        raise _CorruptContainer
    main_part, document_format = matching[0]
    if main_part not in member_names:
        raise _CorruptContainer
    return document_format


def _is_whitespace(value: str | None) -> bool:
    return value is None or not value.strip()


def _create_snapshot() -> tuple[BinaryIO, Path]:
    """Create a private snapshot, closing and removing it on setup failure."""
    descriptor = -1
    snapshot_path: Path | None = None
    try:
        descriptor, snapshot_name = tempfile.mkstemp()
        snapshot_path = Path(snapshot_name)
        snapshot = os.fdopen(descriptor, "w+b", closefd=True)
        descriptor = -1
        return snapshot, snapshot_path
    except (MemoryError, OSError, RuntimeError, ValueError):
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if snapshot_path is not None:
            try:
                snapshot_path.unlink()
            except OSError:
                pass
        raise


def _inspect_zip(
    snapshot: BinaryIO,
    size: int,
    limits: ScanLimits,
    started: float,
) -> tuple[DocumentFormat, Finding | None]:
    try:
        members = _prescan_central_directory(snapshot, size, limits, started)
    except _ContainerLimit:
        return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
    except _CorruptContainer:
        return DocumentFormat.UNKNOWN, _quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT)
    content_types_member = next(
        (member for member in members if member.name == _CONTENT_TYPES_PART), None
    )
    if content_types_member is None:
        return DocumentFormat.ZIP, None
    if content_types_member.is_directory:
        return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT)
    try:
        snapshot.seek(0)
        with zipfile.ZipFile(snapshot) as archive:
            metadata = archive.getinfo(_CONTENT_TYPES_PART)
            with archive.open(metadata) as content_types:
                contents = content_types.read(limits.max_container_member_bytes + 1)
        if len(contents) > limits.max_container_member_bytes:
            return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
        if not _within_time_limit(started, limits):
            return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
        return _parse_content_types(contents, members), None
    except _CorruptContainer:
        return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT)
    except (EOFError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile):
        return DocumentFormat.UNKNOWN, _quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT)


_EXTENSIONS = {
    DocumentFormat.TEXT: frozenset({".txt", ".text", ".md", ".csv"}),
    DocumentFormat.PDF: frozenset({".pdf"}),
    DocumentFormat.ZIP: frozenset({".zip"}),
    DocumentFormat.DOCX: frozenset({".docx"}),
    DocumentFormat.PPTX: frozenset({".pptx"}),
    DocumentFormat.XLSX: frozenset({".xlsx"}),
    DocumentFormat.PNG: frozenset({".png"}),
    DocumentFormat.JPEG: frozenset({".jpg", ".jpeg"}),
}


def _extension_matches(document_format: DocumentFormat, suffix: str) -> bool:
    return suffix in _EXTENSIONS.get(document_format, frozenset())


def _classify_snapshot(
    snapshot: BinaryIO,
    size: int,
    path: Path,
    digest: str,
    limits: ScanLimits,
    started: float,
) -> PreflightReport:
    snapshot.seek(0)
    head = snapshot.read(min(_HEAD_BYTES, size))
    document_format = _fixed_signature(head)
    try:
        if document_format is DocumentFormat.UNKNOWN:
            decoder = _text_decoder(head)
            decoder.decode(head, final=False)
            while chunk := snapshot.read(_HASH_CHUNK_BYTES):
                if not _within_time_limit(started, limits):
                    return _failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=size)
                decoder.decode(chunk, final=False)
            decoder.decode(b"", final=True)
            document_format = DocumentFormat.TEXT
        elif document_format is DocumentFormat.ZIP:
            document_format, finding = _inspect_zip(snapshot, size, limits, started)
            if finding is not None:
                return PreflightReport(document_format, digest, size, (finding,))
    except UnicodeDecodeError:
        return _failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=size)
    if not _within_time_limit(started, limits):
        return _failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=size)
    if document_format is DocumentFormat.UNKNOWN:
        return PreflightReport(
            document_format,
            digest,
            size,
            (_quarantine_finding(EvidenceCode.UNSUPPORTED_FORMAT),),
        )
    if not _extension_matches(document_format, path.suffix.lower()):
        return PreflightReport(
            document_format,
            digest,
            size,
            (_quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT),),
        )
    if document_format is DocumentFormat.ZIP:
        return PreflightReport(
            document_format,
            digest,
            size,
            (_quarantine_finding(EvidenceCode.UNSUPPORTED_FORMAT),),
        )
    return PreflightReport(document_format, digest, size, ())


def verify_source(path: Path, limits: ScanLimits) -> VerifiedSource:
    """Atomically snapshot one complete regular source for downstream parsers."""
    started = time.monotonic()
    try:
        expected = path.stat(follow_symlinks=False)
    except OSError as error:
        return VerifiedSource(_failure_report(error), None)
    if not stat.S_ISREG(expected.st_mode) or expected.st_size > limits.max_upload_bytes:
        return VerifiedSource(_failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=expected.st_size), None)
    if not _within_time_limit(started, limits):
        return VerifiedSource(_failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=expected.st_size), None)

    try:
        descriptor = _open_without_following(path)
    except OSError as error:
        return VerifiedSource(_failure_report(error, size=expected.st_size), None)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _same_identity(expected, opened)
            or opened.st_size != expected.st_size
            or opened.st_size > limits.max_upload_bytes
        ):
            return VerifiedSource(_failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=expected.st_size), None)
        digest = hashlib.sha256()
        try:
            snapshot_handle, snapshot_path = _create_snapshot()
        except (MemoryError, OSError, RuntimeError, ValueError) as error:
            return VerifiedSource(_failure_report(error, size=opened.st_size), None)
        snapshot: BinaryIO | None = snapshot_handle
        handed_off = False
        try:
            assert snapshot is not None
            remaining = opened.st_size
            while remaining:
                if not _within_time_limit(started, limits):
                    return VerifiedSource(_failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=opened.st_size), None)
                chunk = os.read(descriptor, min(_HASH_CHUNK_BYTES, remaining))
                if not chunk:
                    return VerifiedSource(_failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=opened.st_size), None)
                snapshot.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                return VerifiedSource(_failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=opened.st_size), None)
            final = os.fstat(descriptor)
            if (
                not _same_identity(opened, final)
                or final.st_size != opened.st_size
                or final.st_mtime_ns != opened.st_mtime_ns
                or final.st_ctime_ns != opened.st_ctime_ns
            ):
                return VerifiedSource(_failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=opened.st_size), None)
            snapshot.flush()
            if os.fstat(snapshot.fileno()).st_size != opened.st_size:
                return VerifiedSource(_failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=opened.st_size), None)
            report = _classify_snapshot(
                snapshot,
                opened.st_size,
                path,
                digest.hexdigest(),
                limits,
                started,
            )
            if report.findings:
                return VerifiedSource(report, None)
            snapshot.close()
            snapshot = None
            os.chmod(snapshot_path, stat.S_IRUSR)
            handed_off = True
            return VerifiedSource(report, snapshot_path)
        except (MemoryError, OSError, RuntimeError, ValueError) as error:
            return VerifiedSource(_failure_report(error, size=opened.st_size), None)
        finally:
            if snapshot is not None:
                snapshot.close()
            if not handed_off and snapshot_path.exists():
                snapshot_path.unlink()
    finally:
        os.close(descriptor)


def inspect_source(path: Path, limits: ScanLimits) -> PreflightReport:
    """Convenience wrapper for callers that need a report but no parser input."""
    with verify_source(path, limits) as verified:
        return verified.report
