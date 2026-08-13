"""Bounded source inspection before any format-specific parser runs."""

import codecs
import hashlib
import os
import stat
import time
import zipfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from .contract import EvidenceCode, Finding, RiskLevel
from .limits import ScanLimits
from .policy import failure_finding, failure_kind_for_exception

_HEAD_BYTES = 8192
_HASH_CHUNK_BYTES = 1024 * 1024


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


class _BoundedFile:
    """Seekable view that prevents ZIP metadata reads beyond a known size."""

    def __init__(self, handle: BinaryIO, size: int) -> None:
        self._handle = handle
        self._size = size
        self._position = 0

    def read(self, size: int = -1) -> bytes:
        if self._position >= self._size:
            return b""
        available = self._size - self._position
        count = available if size < 0 else min(size, available)
        data = self._handle.read(count)
        self._position += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            position = offset
        elif whence == 1:
            position = self._position + offset
        elif whence == 2:
            position = self._size + offset
        else:
            raise ValueError("invalid seek mode")
        if not 0 <= position <= self._size:
            raise ValueError("bounded ZIP access exceeded source size")
        self._handle.seek(position)
        self._position = position
        return position

    def tell(self) -> int:
        return self._position

    def seekable(self) -> bool:
        return True


def _quarantine_finding(evidence: EvidenceCode) -> Finding:
    return Finding(RiskLevel.QUARANTINE, evidence, "file:structure")


def _failed_report(
    evidence: EvidenceCode,
    *,
    size: int = 0,
    sha256: str = "",
) -> PreflightReport:
    return PreflightReport(
        DocumentFormat.UNKNOWN,
        sha256,
        size,
        (_quarantine_finding(evidence),),
    )


def _failure_report(error: BaseException, *, size: int = 0, sha256: str = "") -> PreflightReport:
    return PreflightReport(
        DocumentFormat.UNKNOWN,
        sha256,
        size,
        (failure_finding(failure_kind_for_exception(error)),),
    )


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


def _within_time_limit(started: float, limits: ScanLimits) -> bool:
    return time.monotonic() - started <= limits.max_seconds


def _member_depth(name: str) -> int:
    return len(tuple(part for part in name.replace("\\", "/").split("/") if part))


def _ooxml_format(content_types: bytes) -> DocumentFormat:
    markers = (
        (b"wordprocessingml.document.main+xml", DocumentFormat.DOCX),
        (b"presentationml.presentation.main+xml", DocumentFormat.PPTX),
        (b"spreadsheetml.sheet.main+xml", DocumentFormat.XLSX),
    )
    lowered = content_types.lower()
    for marker, document_format in markers:
        if marker in lowered:
            return document_format
    return DocumentFormat.ZIP


def _inspect_zip(
    handle: BinaryIO,
    size: int,
    limits: ScanLimits,
    started: float,
) -> tuple[DocumentFormat, Finding | None]:
    try:
        archive = zipfile.ZipFile(_BoundedFile(handle, size))
        with archive:
            members = archive.infolist()
            if len(members) > limits.max_container_members:
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            if sum(member.file_size for member in members) > limits.max_container_uncompressed_bytes:
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            if any(_member_depth(member.filename) > limits.max_container_depth for member in members):
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            if not _within_time_limit(started, limits):
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)

            content_types = next(
                (member for member in members if member.filename == "[Content_Types].xml"),
                None,
            )
            if content_types is None:
                return DocumentFormat.ZIP, None
            if content_types.file_size > limits.max_container_member_bytes:
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            with archive.open(content_types) as metadata:
                contents = metadata.read(limits.max_container_member_bytes + 1)
            if len(contents) > limits.max_container_member_bytes:
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            if not _within_time_limit(started, limits):
                return DocumentFormat.ZIP, _quarantine_finding(EvidenceCode.RESOURCE_LIMIT_EXCEEDED)
            return _ooxml_format(contents), None
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


def inspect_source(path: Path, limits: ScanLimits) -> PreflightReport:
    """Hash and classify a regular file without exposing its contents or name."""
    started = time.monotonic()
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        return _failure_report(error)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limits.max_upload_bytes:
        return _failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=metadata.st_size)
    if not _within_time_limit(started, limits):
        return _failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=metadata.st_size)

    digest = hashlib.sha256()
    size = metadata.st_size
    try:
        with path.open("rb", buffering=0) as handle:
            opened_metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_metadata.st_mode) or opened_metadata.st_size > limits.max_upload_bytes:
                return _failed_report(EvidenceCode.RESOURCE_LIMIT_EXCEEDED, size=opened_metadata.st_size)
            size = opened_metadata.st_size
            head = handle.read(min(_HEAD_BYTES, size))
            digest.update(head)
            document_format = _fixed_signature(head)
            decoder = _text_decoder(head) if document_format is DocumentFormat.UNKNOWN else None
            if decoder is not None:
                decoder.decode(head, final=False)

            bytes_read = len(head)
            while bytes_read < size:
                if not _within_time_limit(started, limits):
                    return _failed_report(
                        EvidenceCode.RESOURCE_LIMIT_EXCEEDED,
                        size=size,
                        sha256=digest.hexdigest(),
                    )
                chunk = handle.read(min(_HASH_CHUNK_BYTES, size - bytes_read))
                if not chunk:
                    return _failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=size, sha256=digest.hexdigest())
                digest.update(chunk)
                bytes_read += len(chunk)
                if decoder is not None:
                    decoder.decode(chunk, final=False)
            if decoder is not None:
                decoder.decode(b"", final=True)
                document_format = DocumentFormat.TEXT

            if document_format is DocumentFormat.ZIP:
                handle.seek(0)
                document_format, finding = _inspect_zip(handle, size, limits, started)
                if finding is not None:
                    return PreflightReport(document_format, digest.hexdigest(), size, (finding,))
    except UnicodeDecodeError:
        return _failed_report(EvidenceCode.CORRUPT_DOCUMENT, size=size, sha256=digest.hexdigest())
    except (MemoryError, OSError, RuntimeError, ValueError) as error:
        return _failure_report(error, size=size, sha256=digest.hexdigest())

    if document_format is DocumentFormat.UNKNOWN:
        return _failed_report(EvidenceCode.UNSUPPORTED_FORMAT, size=size, sha256=digest.hexdigest())
    if not _extension_matches(document_format, path.suffix.lower()):
        return PreflightReport(
            document_format,
            digest.hexdigest(),
            size,
            (_quarantine_finding(EvidenceCode.CORRUPT_DOCUMENT),),
        )
    if document_format is DocumentFormat.ZIP:
        return PreflightReport(
            document_format,
            digest.hexdigest(),
            size,
            (_quarantine_finding(EvidenceCode.UNSUPPORTED_FORMAT),),
        )
    return PreflightReport(document_format, digest.hexdigest(), size, ())
