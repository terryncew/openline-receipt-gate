from __future__ import annotations

import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "benchmarks" / "candidate_promotion" / "run_jain_canonical_bind.py"
SPEC = importlib.util.spec_from_file_location("run_jain_canonical_bind", SCRIPT)
assert SPEC and SPEC.loader
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


def _write_sources(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "sources"
    source.mkdir()
    artifacts = []
    for name in m.EXPECTED_FILENAMES:
        (source / name).write_bytes(("fixture:" + name).encode())
        artifacts.append({"filename": name, "source_url": "https://example.test/" + name})
    attestation = tmp_path / "attestation.json"
    attestation.write_text(json.dumps({
        "schema": "openline.cpg001.jain_manual_acquisition_attestation.v0.1",
        "doi": m.EXPECTED_DOI,
        "retrieval_mode": "manual_browser",
        "retrieved_at": "2026-08-23T19:20:00Z",
        "retrieval_note": "synthetic unit fixture",
        "artifacts": artifacts,
    }))
    return source, attestation


def _success_dependencies() -> dict:
    candidates = [
        {"candidate_id": f"ab-{i:03d}", "stage_2017": "Clinical", "approved_2017": False, "assays": {}}
        for i in range(137)
    ]
    source_manifest = {"source_set_sha256": "source-hash", "artifacts": []}
    preflight = {
        "source_manifest": source_manifest,
        "assay_only": {"candidates": candidates, "labels_unsealed": False},
        "correlation_audit": {"high_correlation_pairs": []},
        "preflight_receipt": {
            "observed_sd03_candidate_count": 137,
            "ready_for_label_unseal": True,
            "assay_only_sha256": "assay-hash",
        },
    }
    normalized = {"candidate_count": 137, "candidates": candidates}
    report = {
        "published_candidate_count": 137,
        "complete_case_candidate_count": 131,
        "primary_verdict": {"verdict": "SUPPORTED_WITHIN_SCOPE"},
    }
    return {
        "bind_sources": lambda _root: source_manifest,
        "run_preflight": lambda _root: preflight,
        "unseal_labels": lambda _root, _preflight: normalized,
        "design_load_json": lambda _path: {},
        "run_confirmatory": lambda _norm, _thresholds, _lock: report,
    }


def test_attestation_binds_exact_files(tmp_path: Path) -> None:
    source, attestation_path = _write_sources(tmp_path)
    bound = m.validate_attestation(json.loads(attestation_path.read_text()), source)
    assert [r["filename"] for r in bound["artifacts"]] == list(m.EXPECTED_FILENAMES)
    assert len(bound["attestation_sha256"]) == 64


def test_success_emits_canonical_receipt_and_137_identity_manifest(tmp_path: Path) -> None:
    source, attestation = _write_sources(tmp_path)
    out = tmp_path / "out"
    receipt = m.run_canonical_bind(source, out, attestation, dependencies=_success_dependencies())
    assert receipt["execution_status"] == "COMPLETE"
    assert receipt["evidence_tier"] == "CANONICAL_SOURCE_BOUND_CONFIRMATORY"
    assert receipt["scientific_signal"] == "SUPPORTED_WITHIN_SCOPE"
    cohort = json.loads((out / "JAIN_2017_CANONICAL_COHORT.json").read_text())
    assert cohort["candidate_count"] == 137
    assert len(cohort["candidate_ids"]) == 137


def test_143_row_preflight_fails_closed_without_scientific_verdict(tmp_path: Path) -> None:
    source, attestation = _write_sources(tmp_path)
    deps = _success_dependencies()
    deps["run_preflight"] = lambda _root: {
        "source_manifest": {"source_set_sha256": "source-hash", "artifacts": []},
        "assay_only": {},
        "correlation_audit": {},
        "preflight_receipt": {
            "observed_sd03_candidate_count": 143,
            "ready_for_label_unseal": False,
            "assay_only_sha256": "assay-hash",
        },
    }
    called = {"confirmatory": False}
    deps["run_confirmatory"] = lambda *_args: called.__setitem__("confirmatory", True)
    receipt = m.run_canonical_bind(source, tmp_path / "out", attestation, dependencies=deps)
    assert receipt["execution_status"] == "BLOCKED"
    assert receipt["block_reason"] == "SOURCE_COHORT_MISMATCH"
    assert receipt["scientific_signal"] is None
    assert called["confirmatory"] is False


def test_sd01_sd03_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    source, attestation = _write_sources(tmp_path)
    deps = _success_dependencies()
    def fail_identity(*_args):
        raise ValueError("sd01_sd03_candidate_set_mismatch:missing=['a']:extra=['b']")
    deps["unseal_labels"] = fail_identity
    receipt = m.run_canonical_bind(source, tmp_path / "out", attestation, dependencies=deps)
    assert receipt["block_reason"] == "SOURCE_COHORT_MISMATCH"
    assert receipt["scientific_signal"] is None


def test_bad_doi_attestation_rejected(tmp_path: Path) -> None:
    source, attestation = _write_sources(tmp_path)
    value = json.loads(attestation.read_text())
    value["doi"] = "wrong"
    try:
        m.validate_attestation(value, source)
    except ValueError as exc:
        assert str(exc) == "manual_attestation_doi_invalid"
    else:
        raise AssertionError("bad DOI was accepted")


def test_contract_and_mirror_disposition_are_fail_closed() -> None:
    base = HERE / "benchmarks" / "candidate_promotion"
    contract = json.loads((base / "JAIN_2017_CANONICAL_BIND_CONTRACT.json").read_text())
    disposition = json.loads((base / "JAIN_2017_MIRROR_DISPOSITION.json").read_text())
    assert contract["source_acquisition"]["network_code_in_runner"] is False
    assert contract["source_acquisition"]["third_party_mirror_allowed"] is False
    assert disposition["observed_candidate_count"] == 143
    assert disposition["disposition"] == "SOURCE_COHORT_MISMATCH"
    assert disposition["scientific_verdict"] is None
    assert disposition["projection_to_137_performed"] is False
