from __future__ import annotations

import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "candidate_promotion"
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from fetch_jain_sources import REQUIRED_FILES, acquire_sources, load_source_spec, validate_source_spec


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


def test_r4_source_spec_freezes_only_official_biostudies_public_bases():
    spec = load_source_spec()
    validate_source_spec(spec)
    bases = spec["biostudies_source"]["public_file_bases"]
    assert len(bases) == 6
    assert all(base.startswith("https://www.ebi.ac.uk/") or base.startswith("https://ftp.ebi.ac.uk/") for base in bases)
    assert "github.com" not in spec["allowed_hosts"]
    assert "huggingface.co" not in spec["allowed_hosts"]


def test_r4_public_file_transport_acquires_complete_triplet_before_write(tmp_path: Path):
    payloads = {name: _xlsx_bytes(name) for name in REQUIRED_FILES}
    first_base = load_source_spec()["biostudies_source"]["public_file_bases"][0].rstrip("/")

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        assert url.startswith(first_base + "/")
        filename = url.rsplit("/", 1)[-1]
        return payloads[filename], {
            "resolved_url": url,
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "http_status": 200,
        }

    def json_downloader(*args, **kwargs):
        raise AssertionError("R4 public transport should finish before /info")

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-04",
    )
    assert receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET"
    assert receipt["execution_id"] == "CPG-001-JAIN-EVIDENCE-04"
    assert len(receipt["artifacts"]) == 3
    assert all(item["source_authority"] == "EMBL_EBI_BIOSTUDIES_PUBLIC_FILE" for item in receipt["artifacts"])
    assert all(len(item["sha256"]) == 64 for item in receipt["artifacts"])
    assert sorted(path.name for path in (tmp_path / "sources").glob("*.xlsx")) == sorted(REQUIRED_FILES)


def test_r4_public_transport_tries_next_frozen_base_as_whole_family(tmp_path: Path):
    payloads = {name: _xlsx_bytes(name) for name in REQUIRED_FILES}
    spec = load_source_spec()
    first = spec["biostudies_source"]["public_file_bases"][0].rstrip("/")
    second = spec["biostudies_source"]["public_file_bases"][1].rstrip("/")

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        if url.startswith(second + "/"):
            filename = url.rsplit("/", 1)[-1]
            return payloads[filename], {"resolved_url": url, "content_type": "application/octet-stream", "http_status": 200}
        if url.startswith(first + "/"):
            raise ValueError("simulated_first_family_block")
        raise AssertionError(f"unexpected transport: {url}")

    def json_downloader(*args, **kwargs):
        raise AssertionError("second public base should finish before /info")

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-04",
    )
    assert receipt["status"].startswith("ACQUIRED_")
    assert any(a["mode"] == "BIOSTUDIES_PUBLIC_FILE" and a["status"] == "REJECTED" for a in receipt["attempts"])
    accepted = [a for a in receipt["attempts"] if a["mode"] == "BIOSTUDIES_PUBLIC_FILE" and a["status"] == "ACCEPTED"]
    assert len(accepted) == 3
    assert all(a["base_url"] == second for a in accepted)


def test_r4_partial_public_family_never_leaks_files_before_fallback(tmp_path: Path):
    payloads = {name: _xlsx_bytes(name) for name in REQUIRED_FILES}

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        if "biostudies/files/" in url:
            filename = url.rsplit("/", 1)[-1]
            if filename.endswith("sd02.xlsx"):
                raise ValueError("simulated_second_file_block")
            return payloads[filename], {"resolved_url": url, "content_type": "application/octet-stream", "http_status": 200}
        raise ValueError("all_other_transports_blocked")

    def json_downloader(*args, **kwargs):
        raise ValueError("info_blocked")

    source_dir = tmp_path / "sources"
    receipt = acquire_sources(
        source_dir,
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-04",
    )
    assert receipt["status"] == "BLOCKED_SOURCE_ACQUISITION"
    assert list(source_dir.glob("*.xlsx")) == []


def test_r3_execution_semantics_remain_info_first(tmp_path: Path):
    payloads = {name: _xlsx_bytes(name) for name in REQUIRED_FILES}

    def json_downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        return {
            "relPath": "S-EPMC/111/S-EPMC5293111",
            "ftpLink": "ftp://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/111/S-EPMC5293111",
        }, {"resolved_url": url, "content_type": "application/json", "http_status": 200}

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        assert url.startswith("https://ftp.ebi.ac.uk/biostudies/fire/S-EPMC/111/S-EPMC5293111/Files/")
        filename = url.rsplit("/", 1)[-1]
        return payloads[filename], {"resolved_url": url, "content_type": "application/octet-stream", "http_status": 200}

    receipt = acquire_sources(
        tmp_path / "sources",
        downloader=downloader,
        json_downloader=json_downloader,
        prefer_biostudies=True,
        execution_id="CPG-001-JAIN-EVIDENCE-03",
    )
    assert receipt["status"].startswith("ACQUIRED_")
    assert not any(a["mode"] == "BIOSTUDIES_PUBLIC_FILE" for a in receipt["attempts"])
