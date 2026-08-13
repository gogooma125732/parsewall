"""Bounded XLSX scanner that never evaluates formulas."""

import re

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

_CHECK = "xlsx-structure-values"
_CELL = re.compile(r"^([A-Z]{1,5})([1-9][0-9]{0,6})$")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _failure(error: Exception) -> ParserOutput:
    return ParserOutput(
        (failure_finding(failure_kind_for_exception(error)),),
        "",
        frozenset({_CHECK}),
        frozenset(),
    )


def _column_number(letters: str) -> int:
    value = 0
    for letter in letters:
        value = value * 26 + ord(letter) - 64
    return value


def _shared_strings(package: BoundedZip) -> tuple[str, ...]:
    if not package.has_member("xl/sharedStrings.xml"):
        return ()
    root = package.read_xml("xl/sharedStrings.xml")
    return tuple(
        "".join(node.text or "" for node in item.iter() if _local(node.tag) == "t")
        for item in root
        if _local(item.tag) == "si"
    )


def scan_xlsx(source: VerifiedSource, limits: ScanLimits) -> ParserOutput:
    try:
        if source.report.format is not DocumentFormat.XLSX or source.report.findings:
            raise ValueError("invalid XLSX source")
        deadline = Deadline.from_limits(limits)
        findings: list[Finding] = []
        output_rows: list[str] = []
        with BoundedZip(source, limits) as package:
            if any(name.casefold().endswith("vbaproject.bin") for name in package.names()):
                findings.append(
                    Finding(
                        RiskLevel.QUARANTINE,
                        EvidenceCode.ACTIVE_CONTENT_PRESENT,
                        "file:structure",
                        AnomalyCode.MACRO_CONTENT,
                    )
                )
            shared = _shared_strings(package)
            workbook = package.read_xml("xl/workbook.xml")
            relationship_targets: dict[str, str] = {}
            if package.has_member("xl/_rels/workbook.xml.rels"):
                rels = package.read_xml("xl/_rels/workbook.xml.rels")
                for rel in rels:
                    if _local(rel.tag) == "Relationship":
                        relationship_targets[rel.attrib.get("Id", "")] = rel.attrib.get("Target", "")
                findings.extend(
                    inspect_relationships(
                        package,
                        "xl/_rels/workbook.xml.rels",
                        "file:structure",
                    )
                )
            sheets = (node for node in workbook.iter() if _local(node.tag) == "sheet")
            for sheet_index, sheet in enumerate(sheets, 1):
                deadline.check()
                state = sheet.attrib.get("state", "visible").casefold()
                rel_id = next(
                    (value for key, value in sheet.attrib.items() if _local(key) == "id"),
                    "",
                )
                target = relationship_targets.get(rel_id, f"worksheets/sheet{sheet_index}.xml")
                target = target.lstrip("/")
                path = target if target.startswith("xl/") else f"xl/{target}"
                if state != "visible":
                    findings.append(
                        Finding(
                            RiskLevel.REVIEW,
                            EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                            f"xlsx:sheet={sheet_index}:row=1:column=1",
                            AnomalyCode.HIDDEN_SHEET,
                        )
                    )
                if not package.has_member(path):
                    raise ValueError("worksheet missing")
                root = package.read_xml(path)
                hidden_rows: set[int] = set()
                hidden_columns: set[int] = set()
                for node in root.iter():
                    local = _local(node.tag)
                    if local == "row" and node.attrib.get("hidden") in {"1", "true"}:
                        hidden_rows.add(int(node.attrib.get("r", "1")))
                    if local == "col" and node.attrib.get("hidden") in {"1", "true"}:
                        start = int(node.attrib.get("min", "1"))
                        end = min(int(node.attrib.get("max", str(start))), 16_384)
                        hidden_columns.update(range(start, end + 1))
                rows: dict[int, dict[int, str]] = {}
                for cell in (node for node in root.iter() if _local(node.tag) == "c"):
                    reference = cell.attrib.get("r", "")
                    matched = _CELL.fullmatch(reference)
                    if matched is None:
                        raise ValueError("invalid cell reference")
                    column = _column_number(matched.group(1))
                    row = int(matched.group(2))
                    location = f"xlsx:sheet={sheet_index}:row={row}:column={column}"
                    formula = next(
                        (child.text or "" for child in cell if _local(child.tag) == "f"),
                        "",
                    )
                    if formula:
                        lowered = formula.casefold()
                        if any(token in lowered for token in ("dde", "webservice(", "http:", "https:", "[")):
                            findings.append(
                                Finding(
                                    RiskLevel.QUARANTINE,
                                    EvidenceCode.ACTIVE_CONTENT_PRESENT,
                                    location,
                                )
                            )
                    raw = next(
                        (child.text or "" for child in cell if _local(child.tag) == "v"),
                        "",
                    )
                    value = raw
                    if cell.attrib.get("t") == "s" and raw:
                        index = int(raw)
                        if index >= len(shared):
                            raise ValueError("shared string out of range")
                        value = shared[index]
                    hidden = state != "visible" or row in hidden_rows or column in hidden_columns
                    findings.extend(classify_instruction(value, hidden=hidden, location=location))
                    findings.extend(encoded_block_findings(value, location=location))
                    if hidden and value:
                        anomaly = (
                            AnomalyCode.HIDDEN_SHEET
                            if state != "visible"
                            else AnomalyCode.HIDDEN_ROW
                            if row in hidden_rows
                            else AnomalyCode.HIDDEN_COLUMN
                        )
                        findings.append(
                            Finding(
                                RiskLevel.REVIEW,
                                EvidenceCode.VISIBLE_EXTRACTED_TEXT_MISMATCH,
                                location,
                                anomaly,
                            )
                        )
                    elif value:
                        rows.setdefault(row, {})[column] = value
                if state == "visible":
                    for row_number in sorted(rows):
                        values = rows[row_number]
                        last = max(values)
                        output_rows.append("\t".join(values.get(column, "") for column in range(1, last + 1)))
        visible = normalize_visible_text("\n".join(output_rows), check_deadline=deadline.check)
        return ParserOutput(tuple(findings), visible, frozenset({_CHECK}), frozenset({_CHECK}))
    except Exception as error:  # noqa: BLE001
        return _failure(error)
