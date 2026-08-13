"""PPTX package inspection plus rendered-slide OCR scanner."""

import re
import tempfile
from pathlib import Path
from xml.etree.ElementTree import Element

import pymupdf as fitz  # type: ignore[import-untyped]

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..executables import ExecutablePolicy, ocr_image, render_presentation
from ..limits import ScanLimits
from ..ooxml import BoundedZip, inspect_relationships
from ..patterns import classify_instruction, normalize_visible_text
from ..policy import FailureKind, failure_finding
from ..preflight import DocumentFormat, VerifiedSource
from .base import Deadline, ParserOutput

_CHECKS = frozenset({"pptx-structure", "pptx-render", "pptx-ocr"})
_SLIDE_PATTERN = re.compile(r"^ppt/slides/slide([1-9][0-9]*)\.xml$")


def _failure(kind: FailureKind) -> ParserOutput:
    return ParserOutput((failure_finding(kind),), "", _CHECKS, frozenset())


def _texts(root: Element) -> str:
    return " ".join(node.text or "" for node in root.iter() if node.tag.endswith("}t"))


def _shape_findings(root: Element, slide_number: int) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for shape_number, shape in enumerate(
        (node for node in root.iter() if node.tag.endswith(("}sp", "}graphicFrame"))),
        1,
    ):
        text = _texts(shape)
        if not text:
            continue
        location = f"pptx:slide={slide_number}:shape={shape_number}"
        hidden = False
        anomaly: AnomalyCode | None = None
        for node in shape.iter():
            if node.tag.endswith("}off"):
                x = int(node.attrib.get("x", "0"))
                y = int(node.attrib.get("y", "0"))
                if x < 0 or y < 0 or x > 100_000_000 or y > 100_000_000:
                    hidden, anomaly = True, AnomalyCode.OFF_CANVAS_TEXT
            if node.tag.endswith(("}rPr", "}defRPr")) and int(
                node.attrib.get("sz", "1800")
            ) < 400:
                hidden, anomaly = True, AnomalyCode.TINY_TEXT
            if node.tag.endswith("}srgbClr") and node.attrib.get("val", "").upper() in {
                "FFFFFF",
                "FEFEFE",
            }:
                hidden, anomaly = True, AnomalyCode.WHITE_ON_WHITE_TEXT
            if node.tag.endswith("}alpha") and int(node.attrib.get("val", "100000")) < 1000:
                hidden, anomaly = True, AnomalyCode.TRANSPARENT_TEXT
        if hidden:
            findings.append(
                Finding(
                    RiskLevel.REVIEW,
                    EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                    location,
                    anomaly,
                )
            )
        findings.extend(classify_instruction(text, hidden=hidden, location=location))
    return tuple(findings)


def _package_findings(
    source: VerifiedSource, limits: ScanLimits
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    with BoundedZip(source, limits) as package:
        names = package.names()
        if any(name.casefold().endswith("vbaproject.bin") for name in names):
            findings.append(
                Finding(
                    RiskLevel.QUARANTINE,
                    EvidenceCode.ACTIVE_CONTENT_PRESENT,
                    "file:structure",
                    AnomalyCode.MACRO_CONTENT,
                )
            )
        findings.extend(
            inspect_relationships(package, "ppt/_rels/presentation.xml.rels", "file:structure")
        )
        for name in names:
            match = _SLIDE_PATTERN.match(name)
            if match:
                slide_number = int(match.group(1))
                root = package.read_xml(name)
                findings.extend(_shape_findings(root, slide_number))
                rel_name = f"ppt/slides/_rels/slide{slide_number}.xml.rels"
                findings.extend(inspect_relationships(package, rel_name, "file:structure"))
            elif name.startswith("ppt/notesSlides/notesSlide") and name.endswith(".xml"):
                notes = _texts(package.read_xml(name))
                if notes:
                    findings.append(
                        Finding(
                            RiskLevel.REVIEW,
                            EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                            "file:structure",
                            AnomalyCode.SPEAKER_NOTES,
                        )
                    )
                    findings.extend(
                        classify_instruction(notes, hidden=True, location="file:structure")
                    )
        if package.has_member("ppt/presentation.xml"):
            presentation = package.read_xml("ppt/presentation.xml")
            if any(
                node.tag.endswith("}sldId")
                and node.attrib.get("show", "1").casefold() in {"0", "false", "off"}
                for node in presentation.iter()
            ):
                findings.append(
                    Finding(
                        RiskLevel.REVIEW,
                        EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                        "file:structure",
                        AnomalyCode.HIDDEN_SLIDE,
                    )
                )
    return tuple(findings)


def scan_pptx(
    source: VerifiedSource,
    limits: ScanLimits,
    policy: ExecutablePolicy | None,
) -> ParserOutput:
    if policy is None or policy.libreoffice is None:
        return _failure(FailureKind.DEPENDENCY)
    try:
        if source.report.format is not DocumentFormat.PPTX:
            raise ValueError("invalid PPTX source")
        deadline = Deadline.from_limits(limits)
        findings = list(_package_findings(source, limits))
        with source.open() as reader:
            contents = reader.read(source.report.size + 1)
        if len(contents) != source.report.size:
            raise ValueError("PPTX size changed")
        visible_slides: list[str] = []
        with tempfile.TemporaryDirectory(prefix="dif-pptx-") as temporary:
            directory = Path(temporary)
            presentation_path = directory / "source.pptx"
            presentation_path.write_bytes(contents)
            presentation_path.chmod(0o600)
            rendered = render_presentation(presentation_path, directory, policy, limits)
            with fitz.open(rendered) as document:
                if document.page_count > limits.max_pages:
                    raise MemoryError
                for slide_number, page in enumerate(document, 1):
                    deadline.check()
                    pixmap = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
                    if pixmap.width * pixmap.height > limits.max_pixels:
                        raise MemoryError
                    image_path = directory / f"slide-{slide_number}.png"
                    pixmap.save(image_path)
                    ocr_text = normalize_visible_text(ocr_image(image_path, policy, limits))
                    visible_slides.append(ocr_text)
                    findings.extend(
                        classify_instruction(
                            ocr_text,
                            hidden=False,
                            location=f"pptx:slide={slide_number}:shape=1",
                        )
                    )
        deadline.check()
        return ParserOutput(
            tuple(findings),
            normalize_visible_text("\n\n".join(visible_slides)),
            _CHECKS,
            _CHECKS,
        )
    except (FileNotFoundError, ImportError):
        return _failure(FailureKind.DEPENDENCY)
    except (MemoryError, TimeoutError):
        return _failure(FailureKind.RESOURCE_LIMIT)
    except Exception:  # noqa: BLE001 -- public parser boundary is fail-closed.
        return _failure(FailureKind.PARSER)
