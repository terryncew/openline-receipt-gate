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
    EUROPE_PMC_ARCHIVE_URL,
    acquire_sources,
    load_source_spec,
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


def _archive_bytes(include_all: bool = True) -> bytes:
    filenames = [
        "pnas.1616408114.sd01.xlsx",
        "pnas.1616408114.sd02.xlsx",
        "pnas.1616408114.sd03.xlsx",
    ]
    if not include_all:
        filenames = filenames[:2]
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", "official supplementary bundle")
        for filename in filenames:
            archive.writestr("supp/" + filename, _xlsx_bytes(filename))
    return stream.getvalue()


def test_frozen_source_spec_adds_only_official_europe_pmc_archive():
    spec = load_source_spec()
    assert "www.ebi.ac.uk" in spec["allowed_hosts"]
    assert "github.com" not in spec["allowed_hosts"]
    assert "huggingface.co" not in spec["allowed_hosts"]
    assert len(spec["archive_sources"]) == 1
    archive = spec["archive_sources"][0]
    assert archive["url"] == EUROPE_PMC_ARCHIVE_URL
    assert archive["authority"] == "PMC International archival mirror"


def test_archive_path_acquires_exact_three_xlsx_members(tmp_path: Path):
    payload = _archive_bytes(include_all=True)

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        assert url == EUROPE_PMC_ARCHIVE_URL
        return payload, {
            "resolved_url": url,
            "content_type": "application/zip",
            "http_status": 200,
        }

    receipt = acquire_sources(tmp_path / "sources", downloader=downloader)
    assert receipt["status"] == "ACQUIRED_CANONICAL_OR_ARCHIVAL_SOURCE_SET"
    assert receipt["execution_id"] == "CPG-001-JAIN-EVIDENCE-02"
    assert len(receipt["artifacts"]) == 3
    assert all(
        artifact["source_authority"] == "EUROPE_PMC_PMC_INTERNATIONAL_ARCHIVE"
        for artifact in receipt["artifacts"]
    )
    assert receipt["processed_mirror_fallback_used"] is False


def test_archive_missing_member_then_blocked_direct_paths_fails_closed(tmp_path: Path):
    payload = _archive_bytes(include_all=False)

    def downloader(url: str, allowed_hosts: set[str], timeout: float, max_bytes: int):
        if url == EUROPE_PMC_ARCHIVE_URL:
            return payload, {
                "resolved_url": url,
                "content_type": "application/zip",
                "http_status": 200,
            }
        raise ValueError("simulated_direct_block")

    source_dir = tmp_path / "sources"
    receipt = acquire_sources(source_dir, downloader=downloader)
    assert receipt["status"] == "BLOCKED_SOURCE_ACQUISITION"
    assert receipt["processed_mirror_fallback_used"] is False
    assert list(source_dir.glob("*.xlsx")) == []
