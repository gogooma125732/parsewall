"""Bounded read-only OOXML container inspection over a VerifiedSource."""

import stat
import zipfile
from pathlib import PurePosixPath
from types import TracebackType
from typing import BinaryIO, Self

from defusedxml.ElementTree import fromstring  # type: ignore[import-untyped]

from .contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from .limits import ScanLimits
from .preflight import VerifiedSource


class ContainerViolation(Exception):
    """The package cannot be safely and completely inspected."""


class BoundedZip:
    def __init__(self, source: VerifiedSource, limits: ScanLimits) -> None:
        self.source = source
        self.limits = limits
        self._reader: BinaryIO | None = None
        self._archive: zipfile.ZipFile | None = None
        self._members: dict[str, zipfile.ZipInfo] = {}

    def __enter__(self) -> Self:
        try:
            reader = self.source.open()
            self._reader = reader
            self._archive = zipfile.ZipFile(reader)
            infos = self._archive.infolist()
            if len(infos) > self.limits.max_container_members:
                raise ContainerViolation
            total = 0
            for info in infos:
                name = info.filename
                pure = PurePosixPath(name)
                if (
                    not name
                    or pure.is_absolute()
                    or ".." in pure.parts
                    or "\\" in name
                    or "\x00" in name
                    or len(pure.parts) > self.limits.max_container_depth
                    or name in self._members
                ):
                    raise ContainerViolation
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ContainerViolation
                if info.file_size > self.limits.max_container_member_bytes:
                    raise ContainerViolation
                total += info.file_size
                if total > self.limits.max_container_uncompressed_bytes:
                    raise ContainerViolation
                if info.compress_size == 0 and info.file_size > 0:
                    raise ContainerViolation
                if info.compress_size and info.file_size / info.compress_size > 200:
                    raise ContainerViolation
                self._members[name] = info
            return self
        except Exception:
            self.close()
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if self._archive is not None:
            self._archive.close()
            self._archive = None
        if self._reader is not None:
            self._reader.close()
            self._reader = None

    def names(self) -> frozenset[str]:
        return frozenset(self._members)

    def has_member(self, name: str) -> bool:
        return name in self._members

    def read_member(self, name: str, max_bytes: int | None = None) -> bytes:
        if self._archive is None or name not in self._members:
            raise ContainerViolation
        bound = min(
            max_bytes or self.limits.max_container_member_bytes,
            self.limits.max_container_member_bytes,
        )
        with self._archive.open(self._members[name]) as member:
            contents = member.read(bound + 1)
        if len(contents) > bound:
            raise ContainerViolation
        return contents

    def read_xml(self, name: str, max_bytes: int | None = None):
        return fromstring(self.read_member(name, max_bytes))


def inspect_relationships(
    package: BoundedZip,
    rel_path: str,
    location: str,
) -> tuple[Finding, ...]:
    if not package.has_member(rel_path):
        return ()
    root = package.read_xml(rel_path)
    findings: list[Finding] = []
    for relationship in root.iter():
        if not relationship.tag.endswith("Relationship"):
            continue
        target_mode = relationship.attrib.get("TargetMode", "").casefold()
        target = relationship.attrib.get("Target", "")
        if target_mode == "external" or target.casefold().startswith(
            ("http:", "https:", "file:", "ftp:")
        ):
            findings.append(
                Finding(
                    RiskLevel.REVIEW,
                    EvidenceCode.EXTERNAL_REFERENCE_PRESENT,
                    location,
                    AnomalyCode.EXTERNAL_RELATIONSHIP,
                )
            )
    return tuple(findings)
