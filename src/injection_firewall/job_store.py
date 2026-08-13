"""Private single-use job namespace for upload and result persistence."""

import os
import re
import secrets
import stat
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO

from .contract import RiskLevel, ScanResult
from .derivative import compact_result_json
from .limits import ScanLimits

_JOB_ID = re.compile(r"^[a-f0-9]{32}$")
_SUFFIXES = frozenset(
    {".txt", ".md", ".markdown", ".html", ".htm", ".docx", ".pptx", ".xlsx", ".pdf", ".png", ".jpg", ".jpeg"}
)


class JobStatus(StrEnum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class JobRecord:
    job_id: str
    status: JobStatus


class JobStore:
    """Own every pathname under a private root; callers supply no output paths."""

    def __init__(self, root: Path, limits: ScanLimits | None = None) -> None:
        if root.is_symlink():
            raise PermissionError("job store symlinks are forbidden")
        self.root = root.resolve(strict=False)
        self.limits = limits or ScanLimits()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat(follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
            raise PermissionError("job store must be a private directory")

    def _job_dir(self, job_id: str) -> Path:
        if not _JOB_ID.fullmatch(job_id):
            raise KeyError("unknown job")
        return self.root / job_id

    def create(self, filename: str, source: BinaryIO) -> JobRecord:
        suffix = Path(filename).suffix.casefold()
        if suffix not in _SUFFIXES:
            suffix = ".unsupported"
        for _ in range(8):
            job_id = secrets.token_hex(16)
            directory = self._job_dir(job_id)
            try:
                directory.mkdir(mode=0o700)
                break
            except FileExistsError:
                continue
        else:
            raise RuntimeError("job allocation failed")
        input_path = directory / f"input{suffix}"
        descriptor = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        written = 0
        try:
            while chunk := source.read(1024 * 1024):
                written += len(chunk)
                if written > self.limits.max_upload_bytes:
                    raise MemoryError("upload too large")
                view = memoryview(chunk)
                while view:
                    count = os.write(descriptor, view)
                    if count <= 0:
                        raise OSError("short upload write")
                    view = view[count:]
            os.fsync(descriptor)
        except Exception:
            try:
                os.close(descriptor)
            finally:
                input_path.unlink(missing_ok=True)
                directory.rmdir()
            raise
        os.close(descriptor)
        self._write_exclusive(directory / "pending", b"1\n")
        return JobRecord(job_id, JobStatus.PENDING)

    @staticmethod
    def _write_exclusive(path: Path, contents: bytes) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            view = memoryview(contents)
            while view:
                count = os.write(descriptor, view)
                if count <= 0:
                    raise OSError("short store write")
                view = view[count:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _publish_atomic(self, directory: Path, name: str, contents: bytes) -> None:
        temporary = directory / f".{name}-{secrets.token_hex(8)}"
        self._write_exclusive(temporary, contents)
        try:
            os.link(temporary, directory / name, follow_symlinks=False)
            directory_descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            temporary.unlink(missing_ok=True)

    def claim(self, job_id: str) -> Path | None:
        directory = self._job_dir(job_id)
        if not (directory / "pending").is_file() or (directory / "result.json").exists():
            return None
        try:
            self._write_exclusive(directory / "claimed", b"1\n")
        except FileExistsError:
            return None
        inputs = tuple(directory.glob("input.*"))
        if len(inputs) != 1 or inputs[0].is_symlink() or not inputs[0].is_file():
            raise ValueError("invalid job input")
        return inputs[0]

    def pending_ids(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                child.name
                for child in self.root.iterdir()
                if child.is_dir() and _JOB_ID.fullmatch(child.name) and (child / "pending").is_file()
            )
        )

    def publish(self, job_id: str, result: ScanResult, derivative: str | None) -> None:
        directory = self._job_dir(job_id)
        if not (directory / "claimed").is_file() or (directory / "result.json").exists():
            raise ValueError("job is not claimable")
        if result.risk_level is not RiskLevel.LOW and derivative is not None:
            raise ValueError("non-low derivative rejected")
        if derivative is not None:
            self._write_exclusive(directory / "derivative.txt", derivative.encode("utf-8"))
        self._publish_atomic(directory, "result.json", compact_result_json(result))
        (directory / "pending").unlink(missing_ok=True)

    def record(self, job_id: str) -> JobRecord:
        directory = self._job_dir(job_id)
        if not directory.is_dir():
            raise KeyError("unknown job")
        if (directory / "result.json").is_file():
            status = JobStatus.COMPLETE
        elif (directory / "claimed").is_file():
            status = JobStatus.PROCESSING
        else:
            status = JobStatus.PENDING
        return JobRecord(job_id, status)

    def result(self, job_id: str) -> ScanResult:
        path = self._job_dir(job_id) / "result.json"
        contents = path.read_bytes()
        return ScanResult.model_validate_json(contents)

    def derivative(self, job_id: str) -> str:
        result = self.result(job_id)
        if result.risk_level is not RiskLevel.LOW:
            raise KeyError("derivative unavailable")
        return (self._job_dir(job_id) / "derivative.txt").read_text(encoding="utf-8")
