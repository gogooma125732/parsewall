"""Hard resource bounds used before document parsing begins."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Explicit, conservative limits for every scanner input dimension."""

    max_upload_bytes: int = 50 * 1024 * 1024
    max_container_members: int = 10_000
    max_container_depth: int = 8
    max_container_member_bytes: int = 1 * 1024 * 1024
    max_container_uncompressed_bytes: int = 100 * 1024 * 1024
    max_container_directory_bytes: int = 4 * 1024 * 1024
    max_pages: int = 10_000
    max_pixels: int = 100_000_000
    max_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (
            self.max_upload_bytes < 1
            or self.max_container_members < 1
            or self.max_container_depth < 1
            or self.max_container_member_bytes < 1
            or self.max_container_uncompressed_bytes < 1
            or self.max_container_directory_bytes < 1
            or self.max_pages < 1
            or self.max_pixels < 1
            or self.max_seconds <= 0
        ):
            raise ValueError("scan limits must be positive")
