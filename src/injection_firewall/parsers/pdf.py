"""PDF structure, rendered-page, text-layer, and OCR scanner."""

import io
import tempfile
from pathlib import Path
from typing import Any

import pymupdf as fitz  # type: ignore[import-untyped]
from pypdf import PdfReader

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..executables import ExecutablePolicy, ocr_image
from ..limits import ScanLimits
from ..patterns import classify_instruction, normalize_visible_text
from ..policy import FailureKind, failure_finding
from ..preflight import DocumentFormat, VerifiedSource
from .base import Deadline, ParserOutput

_CHECKS = frozenset({"pdf-structure", "pdf-render", "pdf-ocr"})
_ACTIVE_KEYS = frozenset(
    {"/AA", "/OpenAction", "/JS", "/JavaScript", "/Launch", "/RichMedia", "/XFA"}
)


def _failure(kind: FailureKind) -> ParserOutput:
    return ParserOutput((failure_finding(kind),), "", _CHECKS, frozenset())


def _pdf_structure_findings(contents: bytes, limits: ScanLimits) -> tuple[Finding, ...]:
    reader = PdfReader(io.BytesIO(contents), strict=True)
    if reader.is_encrypted:
        return (
            Finding(
                RiskLevel.QUARANTINE,
                EvidenceCode.ENCRYPTED_DOCUMENT,
                "file:structure",
            ),
        )
    findings: list[Finding] = []
    visited: set[int] = set()
    stack: list[Any] = [reader.trailer]
    budget = min(limits.max_container_members, 50_000)
    while stack and len(visited) < budget:
        value = stack.pop()
        identity = id(value)
        if identity in visited:
            continue
        visited.add(identity)
        try:
            resolved = value.get_object() if hasattr(value, "get_object") else value
        except Exception as error:
            raise ValueError("invalid PDF object") from error
        if isinstance(resolved, dict):
            keys = {str(key) for key in resolved}
            if keys & _ACTIVE_KEYS:
                findings.append(
                    Finding(
                        RiskLevel.QUARANTINE,
                        EvidenceCode.ACTIVE_CONTENT_PRESENT,
                        "file:structure",
                        AnomalyCode.SCRIPT_CONTENT,
                    )
                )
            if "/EmbeddedFiles" in keys:
                findings.append(
                    Finding(
                        RiskLevel.QUARANTINE,
                        EvidenceCode.ACTIVE_CONTENT_PRESENT,
                        "file:structure",
                    )
                )
            if "/URI" in keys or "/GoToR" in keys:
                findings.append(
                    Finding(
                        RiskLevel.REVIEW,
                        EvidenceCode.EXTERNAL_REFERENCE_PRESENT,
                        "file:structure",
                        AnomalyCode.EXTERNAL_RELATIONSHIP,
                    )
                )
            stack.extend(resolved.values())
        elif isinstance(resolved, (list, tuple)):
            stack.extend(resolved)
    if stack:
        raise MemoryError
    return tuple(findings)


def _span_is_hidden(span: dict[str, Any], page_rect: fitz.Rect) -> tuple[bool, AnomalyCode | None]:
    size = float(span.get("size", 0.0))
    if size < 4.0:
        return True, AnomalyCode.TINY_TEXT
    color = int(span.get("color", 0)) & 0xFFFFFF
    if color >= 0xFAFAFA:
        return True, AnomalyCode.WHITE_ON_WHITE_TEXT
    box = fitz.Rect(span.get("bbox", (0, 0, 0, 0)))
    if not page_rect.intersects(box):
        return True, AnomalyCode.OFF_CANVAS_TEXT
    return False, None


def scan_pdf(
    source: VerifiedSource,
    limits: ScanLimits,
    policy: ExecutablePolicy | None,
) -> ParserOutput:
    if policy is None:
        return _failure(FailureKind.DEPENDENCY)
    try:
        if source.report.format is not DocumentFormat.PDF:
            raise ValueError("invalid PDF source")
        deadline = Deadline.from_limits(limits)
        with source.open() as reader:
            contents = reader.read(source.report.size + 1)
        if len(contents) != source.report.size:
            raise ValueError("PDF size changed")
        findings = list(_pdf_structure_findings(contents, limits))
        visible_pages: list[str] = []
        with fitz.open(stream=contents, filetype="pdf") as document:
            if document.needs_pass:
                findings.append(
                    Finding(
                        RiskLevel.QUARANTINE,
                        EvidenceCode.ENCRYPTED_DOCUMENT,
                        "file:structure",
                    )
                )
                return ParserOutput(tuple(findings), "", _CHECKS, _CHECKS)
            if document.page_count > limits.max_pages:
                raise MemoryError
            with tempfile.TemporaryDirectory(prefix="dif-pdf-") as temporary:
                directory = Path(temporary)
                for page_number, page in enumerate(document, 1):
                    deadline.check()
                    location = f"pdf:page={page_number}:object=1"
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    if pixmap.width * pixmap.height > limits.max_pixels:
                        raise MemoryError
                    image_path = directory / f"page-{page_number}.png"
                    pixmap.save(image_path)
                    ocr_text = normalize_visible_text(ocr_image(image_path, policy, limits))
                    visible_pages.append(ocr_text)
                    findings.extend(
                        classify_instruction(ocr_text, hidden=False, location=location)
                    )
                    layer_text = normalize_visible_text(page.get_text("text"))
                    if layer_text.strip() != ocr_text.strip():
                        findings.append(
                            Finding(
                                RiskLevel.REVIEW,
                                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                                location,
                                AnomalyCode.OCR_TEXT_LAYER_MISMATCH,
                            )
                        )
                    hidden_text: list[str] = []
                    text_dict = page.get_text("dict")
                    for block in text_dict.get("blocks", []):
                        for line in block.get("lines", []):
                            for span in line.get("spans", []):
                                hidden, anomaly = _span_is_hidden(span, page.rect)
                                if hidden:
                                    hidden_text.append(str(span.get("text", "")))
                                    if anomaly is not None:
                                        findings.append(
                                            Finding(
                                                RiskLevel.REVIEW,
                                                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                                                location,
                                                anomaly,
                                            )
                                        )
                    if hidden_text:
                        findings.extend(
                            classify_instruction(
                                " ".join(hidden_text), hidden=True, location=location
                            )
                        )
                    layer_only = layer_text if layer_text not in ocr_text else ""
                    if layer_only:
                        findings.extend(
                            classify_instruction(layer_only, hidden=True, location=location)
                        )
        deadline.check()
        return ParserOutput(
            tuple(findings),
            normalize_visible_text("\n\n".join(visible_pages)),
            _CHECKS,
            _CHECKS,
        )
    except (FileNotFoundError, ImportError):
        return _failure(FailureKind.DEPENDENCY)
    except (MemoryError, TimeoutError):
        return _failure(FailureKind.RESOURCE_LIMIT)
    except Exception:  # noqa: BLE001 -- public parser boundary is fail-closed.
        return _failure(FailureKind.PARSER)
