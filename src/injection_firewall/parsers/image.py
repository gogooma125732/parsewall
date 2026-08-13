"""PNG/JPEG pixel, metadata, alpha, and OCR scanner."""

import io
import subprocess
import tempfile
from pathlib import Path

from PIL import Image

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..executables import ExecutablePolicy, ocr_image
from ..limits import ScanLimits
from ..patterns import classify_instruction, normalize_visible_text
from ..policy import FailureKind, failure_finding
from ..preflight import DocumentFormat, VerifiedSource
from .base import Deadline, ParserOutput

_CHECKS = frozenset({"image-decode", "image-ocr"})


def _failure(kind: FailureKind) -> ParserOutput:
    return ParserOutput((failure_finding(kind),), "", _CHECKS, frozenset())


def scan_image(
    source: VerifiedSource,
    limits: ScanLimits,
    policy: ExecutablePolicy | None,
) -> ParserOutput:
    if policy is None:
        return _failure(FailureKind.DEPENDENCY)
    try:
        if source.report.format not in {DocumentFormat.PNG, DocumentFormat.JPEG}:
            raise ValueError("invalid image source")
        deadline = Deadline.from_limits(limits)
        with source.open() as reader:
            contents = reader.read(source.report.size + 1)
        if len(contents) != source.report.size:
            raise ValueError("image size changed")
        findings: list[Finding] = []
        with Image.open(io.BytesIO(contents)) as decoded:
            decoded.load()
            width, height = decoded.size
            if width < 1 or height < 1 or width * height > limits.max_pixels:
                raise MemoryError
            expected = "PNG" if source.report.format is DocumentFormat.PNG else "JPEG"
            if decoded.format != expected:
                raise ValueError("image format mismatch")
            metadata = " ".join(
                value for value in decoded.info.values() if isinstance(value, str)
            )[: limits.max_container_member_bytes]
            findings.extend(
                classify_instruction(metadata, hidden=True, location="file:metadata")
            )
            rgba = decoded.convert("RGBA")
            alpha = rgba.getchannel("A")
            extrema = alpha.getextrema()
            if not isinstance(extrema, tuple):
                raise TypeError("invalid alpha channel")
            minimum_alpha = extrema[0]
            if not isinstance(minimum_alpha, (int, float)):
                raise TypeError("invalid alpha channel")
            alpha_hidden = minimum_alpha < 255
            if alpha_hidden:
                findings.append(
                    Finding(
                        RiskLevel.REVIEW,
                        EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                        "image:region=1",
                        AnomalyCode.TRANSPARENT_TEXT,
                    )
                )
            white = Image.new("RGBA", rgba.size, "white")
            white.alpha_composite(rgba)
            normal = white.convert("RGB")
            with tempfile.TemporaryDirectory(prefix="dif-image-") as temporary:
                directory = Path(temporary)
                normal_path = directory / "normal.png"
                normal.save(normal_path, format="PNG")
                visible_ocr = ocr_image(normal_path, policy, limits)
                if alpha_hidden:
                    black = Image.new("RGBA", rgba.size, "black")
                    black.alpha_composite(rgba)
                    black_path = directory / "alternate.png"
                    black.convert("RGB").save(black_path, format="PNG")
                    alternate_ocr = ocr_image(black_path, policy, limits)
                    if normalize_visible_text(alternate_ocr).strip() != normalize_visible_text(
                        visible_ocr
                    ).strip():
                        findings.append(
                            Finding(
                                RiskLevel.REVIEW,
                                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                                "image:region=1",
                                AnomalyCode.OCR_TEXT_LAYER_MISMATCH,
                            )
                        )
                        findings.extend(
                            classify_instruction(
                                alternate_ocr,
                                hidden=True,
                                location="image:region=1",
                            )
                        )
            findings.extend(
                classify_instruction(
                    visible_ocr,
                    hidden=False,
                    location="image:region=1",
                )
            )
            deadline.check()
            return ParserOutput(
                tuple(findings),
                normalize_visible_text(visible_ocr),
                _CHECKS,
                _CHECKS,
            )
    except (FileNotFoundError, ImportError):
        return _failure(FailureKind.DEPENDENCY)
    except (MemoryError, TimeoutError, subprocess.TimeoutExpired):
        return _failure(FailureKind.RESOURCE_LIMIT)
    except Exception:  # noqa: BLE001 -- public parser boundary is fail-closed.
        return _failure(FailureKind.PARSER)
