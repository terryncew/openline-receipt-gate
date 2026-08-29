from __future__ import annotations
from pathlib import Path
import csv, json, re, zipfile
from .protocol import project_root

REQUIRED_BASENAMES = [
    "severe_drought_events_ensemble.csv",
    "basin_ensemble_spei06.csv",
    "data_TWSA_all_filled_stl.csv",
    "TWSA_recovery_one_95.csv",
    "wa.csv",
    "basin_attr.csv",
]

def _safe_extract(zpath: Path, dest: Path) -> None:
    with zipfile.ZipFile(zpath) as z:
        base = dest.resolve()
        for m in z.infolist():
            target = (dest / m.filename).resolve()
            if not str(target).startswith(str(base)):
                raise ValueError(f"unsafe zip member: {m.filename}")
        z.extractall(dest)

def _find(root: Path, basename: str) -> Path | None:
    xs = list(root.rglob(basename))
    return xs[0] if len(xs) == 1 else None

def _csv_probe(path: Path, sample_n: int = 5) -> dict:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        r = csv.DictReader(f)
        headers = r.fieldnames or []
        rows = []
        for i, row in enumerate(r):
            if i >= sample_n:
                break
            rows.append({k: row.get(k) for k in headers[:30]})
    low = [h.lower() for h in headers]
    return {
        "path": str(path),
        "headers": headers,
        "sample_rows": rows,
        "candidate_id_columns": [h for h in headers if any(x in h.lower() for x in ("basin", "hybas", "id"))],
        "candidate_time_columns": [h for h in headers if any(x in h.lower() for x in ("date", "time", "year", "month", "start", "end"))],
        "candidate_outcome_columns": [h for h in headers if any(x in h.lower() for x in ("recover", "status", "duration", "time"))],
    }

def _scan_author_code(code_root: Path) -> dict:
    patterns = {
        "recovery": re.compile(r"recover", re.I),
        "drought_end": re.compile(r"(drought.{0,20}end|end.{0,20}drought)", re.I),
        "threshold_95": re.compile(r"(^|[^0-9])95([^0-9]|$)", re.I),
        "twsa": re.compile(r"TWSA", re.I),
        "spei": re.compile(r"SPEI", re.I),
    }
    findings = {k: [] for k in patterns}
    files = []
    for p in sorted(code_root.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".r", ".py", ".txt", ".md"}:
            text = p.read_text(encoding="utf-8", errors="replace")
            files.append(str(p.relative_to(code_root)))
            for lineno, line in enumerate(text.splitlines(), 1):
                for k, pat in patterns.items():
                    if pat.search(line) and len(findings[k]) < 80:
                        findings[k].append({
                            "file": str(p.relative_to(code_root)),
                            "line": lineno,
                            "text": line[:400],
                        })
    return {"files": files, "findings": findings}

def inventory(root: Path | None = None) -> dict:
    root = root or project_root()
    raw = root / "data" / "raw"
    work = root / "data" / "work"
    if work.exists():
        import shutil
        shutil.rmtree(work)
    data_dir = work / "data_bundle"
    code_dir = work / "code_bundle"
    data_dir.mkdir(parents=True)
    code_dir.mkdir(parents=True)

    _safe_extract(raw / "data.zip", data_dir)
    _safe_extract(raw / "code.zip", code_dir)

    probes = {}
    missing = []
    for name in REQUIRED_BASENAMES:
        p = _find(data_dir, name)
        if p is None:
            missing.append(name)
        else:
            probes[name] = _csv_probe(p)

    code_scan = _scan_author_code(code_dir)
    result = {
        "required_files": REQUIRED_BASENAMES,
        "missing_required": missing,
        "tables": probes,
        "author_code": code_scan,
    }
    out = root / "artifacts" / "schema_inventory.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    return result
