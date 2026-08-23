from __future__ import annotations

import json
import math
import re
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence
from xml.etree import ElementTree as ET

HERE = Path(__file__).resolve().parent


class JainXlsxError(ValueError):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def validate_xlsx_container(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        raise JainXlsxError(f"xlsx_missing:{source.name}")
    if not zipfile.is_zipfile(source):
        raise JainXlsxError(f"xlsx_not_zip:{source.name}")
    with zipfile.ZipFile(source) as archive:
        names = set(archive.namelist())
        required = {"[Content_Types].xml", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
        missing = sorted(required - names)
        if missing:
            raise JainXlsxError(f"xlsx_core_parts_missing:{source.name}:{','.join(missing)}")
        worksheet_parts = sorted(name for name in names if name.startswith("xl/worksheets/") and name.endswith(".xml"))
        if not worksheet_parts:
            raise JainXlsxError(f"xlsx_worksheet_missing:{source.name}")
        try:
            ET.fromstring(archive.read("xl/workbook.xml"))
            ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        except ET.ParseError as exc:
            raise JainXlsxError(f"xlsx_xml_invalid:{source.name}") from exc
    return {"filename": source.name, "valid": True, "worksheet_part_count": len(worksheet_parts)}


def _first_sheet_path(archive: zipfile.ZipFile) -> tuple[str, str]:
    workbook = ET.fromstring(archive.read("xl/workbook.xml"))
    first_sheet = next((node for node in workbook.iter() if _local(node.tag) == "sheet"), None)
    if first_sheet is None:
        raise JainXlsxError("xlsx_workbook_has_no_sheet")
    sheet_name = str(first_sheet.attrib.get("name", ""))
    rel_id = None
    for key, value in first_sheet.attrib.items():
        if key.endswith("}id") or key == "r:id":
            rel_id = value
            break
    if not rel_id:
        raise JainXlsxError("xlsx_sheet_relationship_missing")
    rels = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    target = None
    for node in rels.iter():
        if _local(node.tag) == "Relationship" and node.attrib.get("Id") == rel_id:
            target = node.attrib.get("Target")
            break
    if not target:
        raise JainXlsxError("xlsx_sheet_target_missing")
    target_path = PurePosixPath(target)
    if target.startswith("/"):
        sheet_path = str(target_path).lstrip("/")
    else:
        sheet_path = str(PurePosixPath("xl") / target_path)
    if sheet_path not in archive.namelist():
        raise JainXlsxError(f"xlsx_sheet_part_missing:{sheet_path}")
    return sheet_name, sheet_path


def _shared_strings(archive: zipfile.ZipFile) -> list[str]:
    if "xl/sharedStrings.xml" not in archive.namelist():
        return []
    root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
    values: list[str] = []
    for si in (node for node in root.iter() if _local(node.tag) == "si"):
        text = "".join((node.text or "") for node in si.iter() if _local(node.tag) == "t")
        values.append(text)
    return values


def _column_index(cell_ref: str) -> int:
    match = re.match(r"^([A-Z]+)", cell_ref.upper())
    if not match:
        raise JainXlsxError(f"xlsx_bad_cell_ref:{cell_ref}")
    value = 0
    for char in match.group(1):
        value = value * 26 + (ord(char) - 64)
    return value - 1


def _cell_value(cell: ET.Element, shared: Sequence[str]) -> Any:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        return "".join((node.text or "") for node in cell.iter() if _local(node.tag) == "t")
    value_node = next((node for node in cell if _local(node.tag) == "v"), None)
    if value_node is None or value_node.text is None:
        return None
    raw = value_node.text
    if cell_type == "s":
        try:
            return shared[int(raw)]
        except (ValueError, IndexError) as exc:
            raise JainXlsxError("xlsx_shared_string_index_invalid") from exc
    if cell_type in {"str", "e"}:
        return raw
    if cell_type == "b":
        return raw == "1"
    try:
        number = float(raw)
    except ValueError:
        return raw
    return int(number) if number.is_integer() else number


def read_first_sheet_rows(path: str | Path) -> tuple[str, list[list[Any]]]:
    source = Path(path)
    validate_xlsx_container(source)
    with zipfile.ZipFile(source) as archive:
        shared = _shared_strings(archive)
        sheet_name, sheet_path = _first_sheet_path(archive)
        root = ET.fromstring(archive.read(sheet_path))
        rows: list[list[Any]] = []
        for row_node in (node for node in root.iter() if _local(node.tag) == "row"):
            values: dict[int, Any] = {}
            for cell in (node for node in row_node if _local(node.tag) == "c"):
                ref = cell.attrib.get("r", "")
                if not ref:
                    continue
                values[_column_index(ref)] = _cell_value(cell, shared)
            if values:
                width = max(values) + 1
                row = [None] * width
                for index, value in values.items():
                    row[index] = value
                rows.append(row)
            else:
                rows.append([])
    return sheet_name, rows


def normalize_header(value: Any) -> str:
    text = "" if value is None else str(value)
    text = unicodedata.normalize("NFKD", text)
    text = "".join(char for char in text if not unicodedata.combining(char))
    text = text.replace("Δ", " delta ").replace("∆", " delta ").replace("λ", " lambda ")
    text = re.sub(r"[^a-zA-Z0-9]+", " ", text).strip().lower()
    return re.sub(r"\s+", " ", text)


def _alias_score(header: str, alias: str) -> int | None:
    h = normalize_header(header)
    a = normalize_header(alias)
    if not a:
        return None
    if h == a:
        return 10_000_000 + len(a)
    pattern = r"(?<![a-z0-9])" + re.escape(a) + r"(?![a-z0-9])"
    if re.search(pattern, h):
        # Prefer the header in which the alias is the more specific description.
        # This disambiguates AC-SINS from Salt-Gradient AC-SINS without hard-coding
        # column positions: identical AC-SINS wording receives a lower score when
        # embedded in the longer salt-gradient header.
        return len(a) * 1000 - max(0, len(h) - len(a))
    return None


def load_column_rules(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else HERE / "JAIN_2017_SD03_COLUMN_RULES.json"
    return json.loads(target.read_text(encoding="utf-8"))


def resolve_sd03_columns(headers: Sequence[Any], rules: Mapping[str, Any] | None = None) -> dict[str, int]:
    spec = dict(rules or load_column_rules())
    targets: dict[str, Sequence[str]] = {"candidate_id": spec["candidate_id"]["aliases"]}
    targets.update({name: item["aliases"] for name, item in spec["assays"].items()})

    # Resolve the most specific concepts first, then let broader aliases use the
    # best remaining column. This prevents AC-SINS from stealing SGAC-SINS while
    # still failing closed when two concepts truly have only one possible column.
    ordered_targets = sorted(
        targets.items(),
        key=lambda item: (-max(len(normalize_header(alias)) for alias in item[1]), item[0]),
    )
    resolved: dict[str, int] = {}
    used_columns: set[int] = set()
    for target, aliases in ordered_targets:
        matches: list[tuple[int, int, str]] = []
        for index, header in enumerate(headers):
            if header is None or index in used_columns:
                continue
            scores = [_alias_score(str(header), alias) for alias in aliases]
            usable = [score for score in scores if score is not None]
            if usable:
                matches.append((max(usable), index, str(header)))
        matches.sort(key=lambda item: (-item[0], item[1]))
        if not matches:
            raise JainXlsxError(f"sd03_required_column_missing:{target}")
        best_score = matches[0][0]
        best = [item for item in matches if item[0] == best_score]
        if len(best) != 1:
            labels = "|".join(item[2] for item in best)
            raise JainXlsxError(f"sd03_column_ambiguous:{target}:{labels}")
        index = best[0][1]
        resolved[target] = index
        used_columns.add(index)
    return resolved


def find_sd03_header(rows: Sequence[Sequence[Any]], rules: Mapping[str, Any] | None = None) -> tuple[int, dict[str, int]]:
    failures: list[str] = []
    for row_index, row in enumerate(rows[:25]):
        try:
            mapping = resolve_sd03_columns(row, rules)
        except JainXlsxError as exc:
            failures.append(str(exc))
            continue
        return row_index, mapping
    sample = ";".join(failures[:5])
    raise JainXlsxError(f"sd03_header_not_found:{sample}")


def _number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return number if math.isfinite(number) else None
    text = str(value).strip()
    if not text or text.lower() in {"na", "n/a", "nan", "nd", "not determined", "not available", "-"}:
        return None
    try:
        number = float(text.replace(",", ""))
    except ValueError:
        return None
    return number if math.isfinite(number) else None


def normalize_sd03_assays(path: str | Path, rules: Mapping[str, Any] | None = None) -> dict[str, Any]:
    sheet_name, rows = read_first_sheet_rows(path)
    header_index, mapping = find_sd03_header(rows, rules)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    assay_names = [name for name in mapping if name != "candidate_id"]
    for row in rows[header_index + 1 :]:
        id_index = mapping["candidate_id"]
        raw_id = row[id_index] if id_index < len(row) else None
        if raw_id is None or not str(raw_id).strip():
            continue
        candidate_id = str(raw_id).strip()
        if candidate_id in seen:
            raise JainXlsxError(f"sd03_duplicate_candidate:{candidate_id}")
        seen.add(candidate_id)
        assays: dict[str, float | None] = {}
        for assay in assay_names:
            index = mapping[assay]
            raw_value = row[index] if index < len(row) else None
            assays[assay] = _number(raw_value)
        candidates.append({
            "candidate_id": candidate_id,
            "stage_2017": None,
            "approved_2017": None,
            "assays": assays,
        })
    candidates.sort(key=lambda item: item["candidate_id"])
    return {
        "sheet_name": sheet_name,
        "header_row_1_based": header_index + 1,
        "column_mapping": mapping,
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
