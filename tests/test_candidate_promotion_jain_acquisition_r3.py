from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from fetch_jain_sources import (
    BIOSTUDIES_ACCESSION,
    BIOSTUDIES_INFO_URL,
    REQUIRED_FILES,
    acquire_sources,
    load_source_spec,
    validate_source_spec,
)


def _xlsx_bytes(label: str) -> bytes:
    stream = io.BytesIO()
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""
    workbook = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"""
    rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""
    sheet = f"""<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{label}</t></is></c></row></sheetData>
</worksheet>"""
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", rels)
        archive.writestr("xl/worksheets/sheet1.xml", sheet)
    return stream.getvalue()


def _info(mode: str = "fire") -> dict:
    return {
        "relPath": "S-EPMC/111/S-EPMC5293111",
        "ftpLink": f"ftp://ftp.ebi.ac.uk/biostudies/{mode}/S-EPMC/111/S-EPMC5293111",
    }


def test_r3_source_spec_freezes_biostudies_accession_and_official_hosts():
    spec = load_source_spec()
    validate_source_spec(spec)
    assert spec["biostudies_source"]["accession"] == BIOSTUDIES_ACCESSION
    assert spec["biostudies_source"]["info_url"] == BIOSTUDIES_INFO_URL
    assert "ftp.ebi.ac.uk" in spec["allowed_hosts"]
    assert "github.com" not in spec["allowed_hosts"]
    assert "huggingface.co" not in spec["allowed_hosts"]


def test_biostudies_r3_acquires_exact_three_and_binds_execution_03(tmp_path: Path):
    payloads = {filename: _xlsx_bytes(filename) for filename in REQUIRED_FILES}

    def json_downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        assert url == BIOSTUDIES_INFO_URL
        return _info("fire"), {
            "resolved_url": url,
            "content_type": "application/json",
            "http_status": 200,
        }

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        filename = url.rsplit("/", 1)[-1]
        assert url.startswith("https://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/111/S-EPMC5293111/Files/")
        return payloads[filename], {
            "resolved_url": url,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "http_status": 200,
        }

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-03",
    )
    assert receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET"
    assert receipt["execution_id"] == "CPG-001-JAIN-EVIDENCE-03"
    assert len(receipt["artifacts"]) == 3
    assert all(item["source_authority"] == "EMBL_EBI_BIOSTUDIES_S_EPMC_IMPORT" for item in receipt["artifacts"])
    assert all(item["biostudies_accession"] == BIOSTUDIES_ACCESSION for item in receipt["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in receipt["artifacts"])
    assert receipt["processed_mirror_fallback_used"] is False


def test_biostudies_r3_accepts_nfs_storage_mode(tmp_path: Path):
    payloads = {filename: _xlsx_bytes(filename) for filename in REQUIRED_FILES}

    def json_downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        return _info("nfs"), {"resolved_url": url, "content_type": "application/json", "http_status": 200}

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        filename = url.rsplit("/", 1)[-1]
        assert "/biostudies/nfs/" in url
        return payloads[filename], {"resolved_url": url, "content_type": "application/octet-stream", "http_status": 200}

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-03",
    )
    assert receipt["status"].startswith("ACQUIRED_")


def test_biostudies_bad_accession_path_falls_through_and_fails_closed(tmp_path: Path):
    def json_downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        return {
            "relPath": "S-EPMC/999/S-EPMC9999999",
            "ftpLink": "ftp://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/999/S-EPMC9999999",
        }, {"resolved_url": url, "content_type": "application/json", "http_status": 200}

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        raise ValueError("all_fallbacks_blocked")

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-03",
    )
    assert receipt["status"] == "BLOCKED_SOURCE_ACQUISITION"
    assert any(a["mode"] == "BIOSTUDIES_INFO" and a["status"] == "REJECTED" for a in receipt["attempts"])
    assert list((tmp_path / "sources").glob("*.xlsx")) == []


def test_biostudies_partial_file_set_is_removed_before_fallback(tmp_path: Path):
    payloads = {filename: _xlsx_bytes(filename) for filename in REQUIRED_FILES}

    def json_downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        return _info("fire"), {"resolved_url": url, "content_type": "application/json", "http_status": 200}

    seen_biostudies_files = 0
    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        nonlocal seen_biostudies_files
        if "ftp.ebi.ac.uk" in url:
            filename = url.rsplit("/", 1)[-1]
            seen_biostudies_files += 1
            if filename.endswith("sd02.xlsx"):
                raise ValueError("simulated_second_file_block")
            return payloads[filename], {"resolved_url": url, "content_type": "application/octet-stream", "http_status": 200}
        raise ValueError("fallback_blocked")

    source_dir = tmp_path / "sources"
    receipt = acquire_sources(
        source_dir,
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-03",
    )
    assert seen_biostudies_files >= 2
    assert receipt["status"] == "BLOCKED_SOURCE_ACQUISITION"
    assert list(source_dir.glob("*.xlsx")) == []
