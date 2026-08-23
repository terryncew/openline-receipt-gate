from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from bind_jain_sources import bind_sources
from jain_xlsx import JainXlsxError, normalize_sd03_assays, resolve_sd03_columns, validate_xlsx_container
from preflight_jain_assays import run_preflight


def _xml_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def write_xlsx(path: Path, rows: list[list[object]], sheet_name: str = "Sheet1") -> None:
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>'''
    workbook = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="{_xml_text(sheet_name)}" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>'''

    def col_name(index: int) -> str:
        index += 1
        out = ""
        while index:
            index, rem = divmod(index - 1, 26)
            out = chr(65 + rem) + out
        return out

    row_xml = []
    for r_index, row in enumerate(rows, start=1):
        cells = []
        for c_index, value in enumerate(row):
            if value is None:
                continue
            ref = f"{col_name(c_index)}{r_index}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{_xml_text(str(value))}</t></is></c>')
        row_xml.append(f'<row r="{r_index}">{"".join(cells)}</row>')
    sheet = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>''' + "".join(row_xml) + "</sheetData></worksheet>"

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("xl/workbook.xml", workbook)
        z.writestr("xl/_rels/workbook.xml.rels", rels)
        z.writestr("xl/worksheets/sheet1.xml", sheet)


def sd03_headers() -> list[str]:
    return [
        "Name",
        "Polyspecificity Reagent (PSR) Average",
        "Affinity-Capture Self-Interaction Nanoparticle Spectroscopy (AC-SINS) Δλmax (nm) Average",
        "Clone Self-Interaction by Bio-Layer Interferometry (CSI-BLI) Average",
        "Cross-Interaction Chromatography (CIC) Average",
        "Hydrophobic Interaction Chromatography (HIC) Average",
        "Stand-up Monolayer Adsorption Chromatography (SMAC) Average",
        "Salt-Gradient Affinity-Capture Self-Interaction Nanoparticle Spectroscopy (SGAC-SINS) Average",
        "Baculovirus Particle (BVP) Average",
        "Enzyme-Linked Immunosorbent Assay (ELISA) Average",
        "Accelerated Stability AS SEC Slope Average",
    ]


def make_sources(tmp_path: Path, count: int = 137) -> Path:
    source = tmp_path / "jain_sources"
    write_xlsx(source / "pnas.1616408114.sd01.xlsx", [["Name", "Status"], ["mAb-001", "SECRET_APPROVAL_LABEL"]], "metadata")
    write_xlsx(source / "pnas.1616408114.sd02.xlsx", [["Name", "VH", "VL"], ["mAb-001", "EVQ", "DIQ"]], "sequences")
    rows: list[list[object]] = [sd03_headers()]
    for i in range(1, count + 1):
        # Correlated PSR/HIC deliberately exercises audit. Values stay finite.
        base = i / 100.0
        rows.append([f"mAb-{i:03d}", base, base * 2, base * 3, base * 4, base, base * 5, 500 - i, base * 6, base * 7, base * 0.01])
    write_xlsx(source / "pnas.1616408114.sd03.xlsx", rows, "biophysical")
    return source


def test_xlsx_container_validation_rejects_non_xlsx(tmp_path: Path):
    bad = tmp_path / "bad.xlsx"
    bad.write_text("not an xlsx", encoding="utf-8")
    try:
        validate_xlsx_container(bad)
    except JainXlsxError as exc:
        assert str(exc).startswith("xlsx_not_zip")
    else:
        raise AssertionError("expected malformed XLSX rejection")


def test_column_resolution_disambiguates_ac_sins_from_sgac_sins():
    mapping = resolve_sd03_columns(sd03_headers())
    assert mapping["AC_SINS"] != mapping["SGAC_SINS"]
    assert set(mapping) == {"candidate_id", "PSR", "AC_SINS", "CSI_BLI", "CIC", "HIC", "SMAC", "SGAC_SINS", "BVP", "ELISA", "AS"}


def test_source_binding_is_deterministic_and_does_not_open_labels(tmp_path: Path):
    source = make_sources(tmp_path)
    first = bind_sources(source)
    second = bind_sources(source)
    assert first["source_set_sha256"] == second["source_set_sha256"]
    assert first["label_seal"]["sd01_cells_opened"] is False
    assert "SECRET_APPROVAL_LABEL" not in json.dumps(first)


def test_source_binding_fails_closed_on_missing_required_artifact(tmp_path: Path):
    source = make_sources(tmp_path)
    (source / "pnas.1616408114.sd02.xlsx").unlink()
    try:
        bind_sources(source)
    except ValueError as exc:
        assert "pnas.1616408114.sd02.xlsx" in str(exc)
    else:
        raise AssertionError("expected missing source failure")


def test_sd03_normalization_keeps_labels_null(tmp_path: Path):
    source = make_sources(tmp_path, count=3)
    parsed = normalize_sd03_assays(source / "pnas.1616408114.sd03.xlsx")
    assert parsed["candidate_count"] == 3
    assert all(row["approved_2017"] is None and row["stage_2017"] is None for row in parsed["candidates"])
    assert set(parsed["candidates"][0]["assays"]) == {"PSR", "AC_SINS", "CSI_BLI", "CIC", "HIC", "SMAC", "SGAC_SINS", "BVP", "ELISA", "AS"}


def test_preflight_seals_assay_artifact_before_label_unseal(tmp_path: Path):
    source = make_sources(tmp_path)
    bundle = run_preflight(source)
    receipt = bundle["preflight_receipt"]
    assert receipt["ready_for_label_unseal"] is True
    assert receipt["observed_sd03_candidate_count"] == 137
    assert receipt["label_seal"]["sd01_cells_opened"] is False
    assert receipt["label_seal"]["approval_or_phase_labels_available_to_preflight"] is False
    assert bundle["assay_only"]["labels_unsealed"] is False
    assert "SECRET_APPROVAL_LABEL" not in json.dumps(bundle)
    assert receipt["high_correlation_pair_count"] > 0
    assert receipt["policy_mutation_allowed"] is False


def test_preflight_refuses_unseal_readiness_on_wrong_row_count(tmp_path: Path):
    source = make_sources(tmp_path, count=136)
    bundle = run_preflight(source)
    assert bundle["preflight_receipt"]["ready_for_label_unseal"] is False
    assert bundle["preflight_receipt"]["observed_candidate_count_ok"] is False
