"""Bounded DOCX structural and visibility scanner."""

from ..contract import AnomalyCode, EvidenceCode, Finding, RiskLevel
from ..limits import ScanLimits
from ..ooxml import BoundedZip, inspect_relationships
from ..patterns import (
    classify_instruction,
    encoded_block_findings,
    normalize_visible_text,
)
from ..policy import failure_finding, failure_kind_for_exception
from ..preflight import DocumentFormat, VerifiedSource
from .base import Deadline, ParserOutput

_CHECK = "docx-structure"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attribute(element, name: str) -> str | None:
    for key, value in element.attrib.items():
        if _local(key) == name:
            return value
    return None


def _run_hidden(run) -> tuple[bool, AnomalyCode | None]:
    properties = next((child for child in run if _local(child.tag) == "rPr"), None)
    if properties is None:
        return False, None
    for child in properties:
        name = _local(child.tag)
        value = (_attribute(child, "val") or "").casefold()
        if name in {"vanish", "webHidden"} and value not in {"0", "false", "off"}:
            return True, AnomalyCode.HIDDEN_XML_TEXT
        if name == "color" and value in {"ffffff", "fff", "white"}:
            return True, AnomalyCode.WHITE_ON_WHITE_TEXT
        if name == "sz":
            try:
                if int(value) < 16:
                    return True, AnomalyCode.TINY_TEXT
            except ValueError:
                return True, AnomalyCode.HIDDEN_XML_TEXT
    return False, None


def _text_of(element) -> str:
    return "".join(item.text or "" for item in element.iter() if _local(item.tag) == "t")


def _failure(error: Exception) -> ParserOutput:
    return ParserOutput(
        (failure_finding(failure_kind_for_exception(error)),),
        "",
        frozenset({_CHECK}),
        frozenset(),
    )


def scan_docx(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    try:
        if source.report.format is not DocumentFormat.DOCX or source.report.findings:
            raise ValueError("invalid DOCX source")
        deadline = Deadline.from_limits(limits)
        findings: list[Finding] = []
        visible_paragraphs: list[str] = []
        with BoundedZip(source, limits) as package:
            deadline.check()
            if any(name.casefold().endswith("vbaproject.bin") for name in package.names()):
                findings.append(
                    Finding(
                        RiskLevel.QUARANTINE,
                        EvidenceCode.ACTIVE_CONTENT_PRESENT,
                        "docx:part=vbaProject.bin",
                        AnomalyCode.MACRO_CONTENT,
                    )
                )
            root = package.read_xml("word/document.xml")
            paragraph_number = 0
            for paragraph in (node for node in root.iter() if _local(node.tag) == "p"):
                deadline.check()
                paragraph_number += 1
                location = f"docx:part=document.xml:paragraph={paragraph_number}"
                visible_runs: list[str] = []
                for run in (node for node in paragraph if _local(node.tag) == "r"):
                    text = _text_of(run)
                    if not text:
                        continue
                    hidden, anomaly = _run_hidden(run)
                    findings.extend(
                        classify_instruction(
                            text,
                            hidden=hidden,
                            location=location,
                            check_deadline=deadline.check,
                        )
                    )
                    findings.extend(
                        encoded_block_findings(
                            text,
                            location=location,
                            check_deadline=deadline.check,
                        )
                    )
                    if hidden:
                        findings.append(
                            Finding(
                                RiskLevel.REVIEW,
                                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                                location,
                                anomaly or AnomalyCode.HIDDEN_XML_TEXT,
                            )
                        )
                    else:
                        visible_runs.append(text)
                if visible_runs:
                    visible_paragraphs.append("".join(visible_runs))

            for name, part in (
                ("word/comments.xml", "comments.xml"),
                ("docProps/core.xml", "core.xml"),
                ("docProps/app.xml", "app.xml"),
            ):
                if not package.has_member(name):
                    continue
                hidden_text = _text_of(package.read_xml(name))
                location = f"docx:part={part}"
                findings.extend(
                    classify_instruction(
                        hidden_text,
                        hidden=True,
                        location=location,
                        check_deadline=deadline.check,
                    )
                )
                if hidden_text.strip():
                    findings.append(
                        Finding(
                            RiskLevel.REVIEW,
                            EvidenceCode.METADATA_INSTRUCTION_PATTERN,
                            location,
                            AnomalyCode.HIDDEN_XML_TEXT,
                        )
                    )
            for rel_path in (
                "word/_rels/document.xml.rels",
                "_rels/.rels",
            ):
                findings.extend(
                    inspect_relationships(package, rel_path, "docx:part=relationships")
                )
        deadline.check()
        visible = normalize_visible_text("\n".join(visible_paragraphs), check_deadline=deadline.check)
        return ParserOutput(
            tuple(findings),
            visible,
            frozenset({_CHECK}),
            frozenset({_CHECK}),
        )
    except Exception as error:  # noqa: BLE001
        return _failure(error)
