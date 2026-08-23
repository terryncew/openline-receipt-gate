from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from fetch_jain_sources import acquire_sources, load_source_spec, validate_source_spec
from jain_design import sha256_json
from preflight_jain_assays import run_preflight
from unseal_jain_labels import unseal_labels


def _xml(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def xlsx_bytes(rows: list[list[object]], sheet_name: str = "Sheet1") -> bytes:
    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>'''
    workbook = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{_xml(sheet_name)}" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'''

    def col(index: int) -> str:
        index += 1
        text = ""
        while index:
            index, rem = divmod(index - 1, 26)
            text = chr(65 + rem) + text
        return text

    xml_rows = []
    for r, row in enumerate(rows, start=1):
        cells = []
        for c, value in enumerate(row):
            if value is None:
                continue
            ref = f"{col(c)}{r}"
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                cells.append(f'<c r="{ref}"><v>{value}</v></c>')
            else:
                cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{_xml(str(value))}</t></is></c>')
        xml_rows.append(f'<row r="{r}">{"".join(cells)}</row>')
    sheet = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' + "".join(xml_rows) + "</sheetData></worksheet>"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
    return stream.getvalue()


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


def source_payloads() -> dict[str, bytes]:
    sd01 = [["Name", "Original mAb Isotype or Format", "Clinical Status"]]
    sd02 = [["Name", "VH", "VL"]]
    sd03 = [sd03_headers()]
    for i in range(1, 138):
        name = f"mAb-{i:03d}"
        sd01.append([name, "IgG1", "Approved" if i <= 48 else ("Phase 3" if i <= 90 else "Phase 2")])
        sd02.append([name, "EVQLVESGG", "DIQMTQSP"])
        base = i / 1000.0
        sd03.append([name, base, base * 2, base * 3, base * 4, base * 5, base * 6, 500 - i, base * 7, base * 8, base * 0.01])
    return {
        "pnas.1616408114.sd01.xlsx": xlsx_bytes(sd01, "Antibody-list"),
        "pnas.1616408114.sd02.xlsx": xlsx_bytes(sd02, "Sequence-information"),
        "pnas.1616408114.sd03.xlsx": xlsx_bytes(sd03, "Results-12-assays"),
    }


def fake_downloader_factory(payloads: dict[str, bytes]):
    def fake(url: str, allowed_hosts: set[str], timeout: float):
        filename = url.rsplit("/", 1)[-1]
        return payloads[filename], {
            "resolved_url": url,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "http_status": 200,
        }
    return fake


def write_preflight_outputs(path: Path, bundle: dict) -> None:
    path.mkdir(parents=True, exist_ok=True)
    mapping = {
        "JAIN_2017_SOURCE_MANIFEST.json": bundle["source_manifest"],
        "JAIN_2017_ASSAY_ONLY.normalized.json": bundle["assay_only"],
        "JAIN_2017_CORRELATION_AUDIT.json": bundle["correlation_audit"],
        "JAIN_2017_ASSAY_PREFLIGHT_RECEIPT.json": bundle["preflight_receipt"],
    }
    for filename, value in mapping.items():
        (path / filename).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def test_source_spec_has_only_frozen_three_and_allowed_https_hosts():
    spec = load_source_spec()
    validate_source_spec(spec)
    assert set(spec["artifacts"]) == {
        "pnas.1616408114.sd01.xlsx",
        "pnas.1616408114.sd02.xlsx",
        "pnas.1616408114.sd03.xlsx",
    }
    assert "github.com" not in spec["allowed_hosts"]
    assert "huggingface.co" not in spec["allowed_hosts"]


def test_source_spec_rejects_processed_mirror():
    spec = load_source_spec()
    spec["allowed_hosts"] = list(spec["allowed_hosts"]) + ["raw.githubusercontent.com"]
    spec["artifacts"]["pnas.1616408114.sd03.xlsx"] = [
        "https://raw.githubusercontent.com/example/repo/main/pnas.1616408114.sd03.xlsx"
    ]
    try:
        validate_source_spec(spec)
    except ValueError as exc:
        assert str(exc) == "allowed_hosts_changed"
    else:
        raise AssertionError("expected mirror rejection")


def test_acquisition_binds_exact_xlsx_trio_without_mirror_fallback(tmp_path: Path):
    payloads = source_payloads()
    receipt = acquire_sources(tmp_path / "sources", downloader=fake_downloader_factory(payloads))
    assert receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET"
    assert receipt["processed_mirror_fallback_used"] is False
    assert len(receipt["artifacts"]) == 3
    assert all(item["xlsx_container_valid"] for item in receipt["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in receipt["artifacts"])


def test_acquisition_fails_closed_if_one_artifact_cannot_be_acquired(tmp_path: Path):
    payloads = source_payloads()
    def fail_sd02(url: str, allowed_hosts: set[str], timeout: float):
        filename = url.rsplit("/", 1)[-1]
        if filename.endswith("sd02.xlsx"):
            raise ValueError("simulated_block")
        return fake_downloader_factory(payloads)(url, allowed_hosts, timeout)
    receipt = acquire_sources(tmp_path / "sources", downloader=fail_sd02)
    assert receipt["status"] == "BLOCKED_SOURCE_ACQUISITION"
    assert receipt["failed_filename"] == "pnas.1616408114.sd02.xlsx"
    assert receipt["processed_mirror_fallback_used"] is False


def test_label_unseal_requires_persisted_assay_seal_and_then_restores_publication_status(tmp_path: Path):
    payloads = source_payloads()
    source_dir = tmp_path / "sources"
    receipt = acquire_sources(source_dir, downloader=fake_downloader_factory(payloads))
    assert receipt["status"].startswith("ACQUIRED_")
    bundle = run_preflight(source_dir)
    assert bundle["preflight_receipt"]["ready_for_label_unseal"] is True
    preflight = tmp_path / "preflight"
    write_preflight_outputs(preflight, bundle)
    normalized = unseal_labels(source_dir, preflight)
    assert normalized["labels_unsealed"] is True
    assert normalized["candidate_count"] == 137
    assert sum(row["approved_2017"] is True for row in normalized["candidates"]) == 48
    assert normalized["assay_only_sha256"] == sha256_json(bundle["assay_only"])


def test_label_unseal_rejects_assay_artifact_changed_after_preflight(tmp_path: Path):
    payloads = source_payloads()
    source_dir = tmp_path / "sources"
    acquire_sources(source_dir, downloader=fake_downloader_factory(payloads))
    bundle = run_preflight(source_dir)
    preflight = tmp_path / "preflight"
    write_preflight_outputs(preflight, bundle)
    assay_path = preflight / "JAIN_2017_ASSAY_ONLY.normalized.json"
    assay = json.loads(assay_path.read_text(encoding="utf-8"))
    assay["candidates"][0]["assays"]["HIC"] = 999.0
    assay_path.write_text(json.dumps(assay, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        unseal_labels(source_dir, preflight)
    except ValueError as exc:
        assert "assay_only_seal_hash_mismatch" in str(exc)
    else:
        raise AssertionError("expected seal mismatch")
