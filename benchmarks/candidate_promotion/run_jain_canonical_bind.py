from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

HERE = Path(__file__).resolve().parent
EXPECTED_FILENAMES = (
    "pnas.1616408114.sd01.xlsx",
    "pnas.1616408114.sd02.xlsx",
    "pnas.1616408114.sd03.xlsx",
)
EXPECTED_DOI = "10.1073/pnas.1616408114"
EXPECTED_CANDIDATES = 137


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_attestation(attestation: Mapping[str, Any], source_dir: Path) -> dict[str, Any]:
    if attestation.get("schema") != "openline.cpg001.jain_manual_acquisition_attestation.v0.1":
        raise ValueError("manual_attestation_schema_invalid")
    if attestation.get("doi") != EXPECTED_DOI:
        raise ValueError("manual_attestation_doi_invalid")
    if attestation.get("retrieval_mode") != "manual_browser":
        raise ValueError("manual_attestation_retrieval_mode_invalid")
    artifacts = attestation.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("manual_attestation_artifacts_invalid")
    by_name = {str(item.get("filename", "")): item for item in artifacts if isinstance(item, Mapping)}
    if set(by_name) != set(EXPECTED_FILENAMES):
        raise ValueError("manual_attestation_filename_set_invalid")
    records: list[dict[str, Any]] = []
    for filename in EXPECTED_FILENAMES:
        path = source_dir / filename
        if not path.is_file():
            raise ValueError(f"canonical_source_missing:{filename}")
        item = by_name[filename]
        source_url = str(item.get("source_url", "")).strip()
        if not source_url.startswith("https://"):
            raise ValueError(f"manual_attestation_source_url_invalid:{filename}")
        records.append({
            "filename": filename,
            "source_url": source_url,
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    stable = {
        "schema": attestation["schema"],
        "doi": EXPECTED_DOI,
        "retrieval_mode": "manual_browser",
        "retrieved_at": attestation.get("retrieved_at"),
        "retrieval_note": attestation.get("retrieval_note"),
        "artifacts": records,
    }
    return {**stable, "attestation_sha256": sha256_json(stable)}


def _dependencies() -> dict[str, Callable[..., Any]]:
    # Imports are intentionally delayed so the orchestration layer can be unit-tested
    # without opening or vendoring the canonical publisher artifacts.
    from bind_jain_sources import bind_sources
    from jain_design import load_json as design_load_json, run_confirmatory
    from preflight_jain_assays import run_preflight
    from unseal_jain_labels import unseal_labels

    return {
        "bind_sources": bind_sources,
        "run_preflight": run_preflight,
        "unseal_labels": unseal_labels,
        "run_confirmatory": run_confirmatory,
        "design_load_json": design_load_json,
    }


def _blocked_receipt(
    *,
    reason: str,
    source_attestation: Mapping[str, Any],
    source_manifest: Mapping[str, Any] | None = None,
    detail: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "openline.cpg001.jain_canonical_run_receipt.v0.1",
        "experiment_id": "CPG-001",
        "execution_id": "CPG-001-JAIN-CANONICAL-01",
        "execution_status": "BLOCKED",
        "evidence_tier": "CANONICAL_SOURCE_BIND_ATTEMPT",
        "scientific_signal": None,
        "block_reason": reason,
        "source_attestation_sha256": source_attestation.get("attestation_sha256"),
        "source_set_sha256": None if source_manifest is None else source_manifest.get("source_set_sha256"),
        "detail": dict(detail or {}),
        "policy_or_threshold_mutation": False,
        "created_at": utc_now(),
    }


def _cohort_manifest(normalized: Mapping[str, Any]) -> dict[str, Any]:
    candidates = normalized.get("candidates")
    if not isinstance(candidates, list):
        raise ValueError("normalized_candidates_invalid")
    ids = sorted(str(row.get("candidate_id", "")) for row in candidates)
    if len(ids) != EXPECTED_CANDIDATES or any(not value for value in ids) or len(set(ids)) != len(ids):
        raise ValueError(f"canonical_identity_manifest_invalid:{len(ids)}")
    stable = {
        "schema": "openline.cpg001.jain_canonical_cohort.v0.1",
        "dataset_id": "JAIN_2017",
        "doi": EXPECTED_DOI,
        "candidate_count": len(ids),
        "candidate_ids": ids,
        "identity_basis": "exact equality of bound SD01 and SD03 candidate sets after assay-only preflight seal",
        "outcome_values_excluded_from_identity_hash": True,
    }
    return {**stable, "candidate_ids_sha256": sha256_json(ids), "manifest_sha256": sha256_json(stable)}


def run_canonical_bind(
    source_dir: str | Path,
    out_dir: str | Path,
    attestation_path: str | Path,
    *,
    dependencies: Mapping[str, Callable[..., Any]] | None = None,
) -> dict[str, Any]:
    source_root = Path(source_dir)
    out_root = Path(out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    preflight_root = out_root / "preflight"
    preflight_root.mkdir(parents=True, exist_ok=True)

    attestation_raw = load_json(Path(attestation_path))
    source_attestation = validate_attestation(attestation_raw, source_root)
    write_json(out_root / "JAIN_2017_MANUAL_ACQUISITION_ATTESTATION.bound.json", source_attestation)

    deps = dict(dependencies or _dependencies())
    source_manifest: Mapping[str, Any] | None = None
    try:
        source_manifest = deps["bind_sources"](source_root)
        write_json(out_root / "JAIN_2017_SOURCE_MANIFEST.json", source_manifest)

        preflight = deps["run_preflight"](source_root)
        write_json(preflight_root / "JAIN_2017_SOURCE_MANIFEST.json", preflight["source_manifest"])
        write_json(preflight_root / "JAIN_2017_ASSAY_ONLY.normalized.json", preflight["assay_only"])
        write_json(preflight_root / "JAIN_2017_CORRELATION_AUDIT.json", preflight["correlation_audit"])
        write_json(preflight_root / "JAIN_2017_ASSAY_PREFLIGHT_RECEIPT.json", preflight["preflight_receipt"])

        receipt = preflight["preflight_receipt"]
        observed = int(receipt.get("observed_sd03_candidate_count", -1))
        if observed != EXPECTED_CANDIDATES or receipt.get("ready_for_label_unseal") is not True:
            blocked = _blocked_receipt(
                reason="SOURCE_COHORT_MISMATCH",
                source_attestation=source_attestation,
                source_manifest=source_manifest,
                detail={
                    "expected_candidate_count": EXPECTED_CANDIDATES,
                    "observed_sd03_candidate_count": observed,
                    "ready_for_label_unseal": receipt.get("ready_for_label_unseal"),
                },
            )
            write_json(out_root / "JAIN_2017_CANONICAL_RUN_RECEIPT.json", blocked)
            return blocked

        normalized = deps["unseal_labels"](source_root, preflight_root)
        if normalized.get("candidate_count") != EXPECTED_CANDIDATES:
            blocked = _blocked_receipt(
                reason="SOURCE_COHORT_MISMATCH",
                source_attestation=source_attestation,
                source_manifest=source_manifest,
                detail={"observed_normalized_candidate_count": normalized.get("candidate_count")},
            )
            write_json(out_root / "JAIN_2017_CANONICAL_RUN_RECEIPT.json", blocked)
            return blocked
        write_json(out_root / "JAIN_2017_CONFIRMATORY.normalized.json", normalized)

        cohort = _cohort_manifest(normalized)
        write_json(out_root / "JAIN_2017_CANONICAL_COHORT.json", cohort)

        thresholds = deps["design_load_json"](HERE / "JAIN_2017_THRESHOLDS.json")
        design_lock = deps["design_load_json"](HERE / "JAIN_2017_DESIGN_LOCK.json")
        report = deps["run_confirmatory"](normalized, thresholds, design_lock)
        write_json(out_root / "JAIN_2017_CONFIRMATORY_REPORT.json", report)

        verdict = report["primary_verdict"]["verdict"]
        transformation = {
            "schema": "openline.cpg001.jain_canonical_transformation_receipt.v0.1",
            "source_attestation_sha256": source_attestation["attestation_sha256"],
            "source_set_sha256": source_manifest["source_set_sha256"],
            "assay_only_sha256": preflight["preflight_receipt"]["assay_only_sha256"],
            "canonical_cohort_sha256": cohort["manifest_sha256"],
            "normalized_sha256": sha256_json(normalized),
            "confirmatory_report_sha256": sha256_json(report),
            "raw_workbooks_committed_to_repo": False,
            "network_access_performed_by_runner": False,
            "policy_or_threshold_mutation": False,
        }
        write_json(out_root / "JAIN_2017_CANONICAL_TRANSFORMATION_RECEIPT.json", transformation)

        final_receipt = {
            "schema": "openline.cpg001.jain_canonical_run_receipt.v0.1",
            "experiment_id": "CPG-001",
            "execution_id": "CPG-001-JAIN-CANONICAL-01",
            "execution_status": "COMPLETE",
            "evidence_tier": "CANONICAL_SOURCE_BOUND_CONFIRMATORY",
            "scientific_signal": verdict,
            "candidate_count": report.get("published_candidate_count"),
            "complete_case_candidate_count": report.get("complete_case_candidate_count"),
            "source_attestation_sha256": source_attestation["attestation_sha256"],
            "source_set_sha256": source_manifest["source_set_sha256"],
            "canonical_cohort_sha256": cohort["manifest_sha256"],
            "confirmatory_report_sha256": transformation["confirmatory_report_sha256"],
            "policy_or_threshold_mutation": False,
            "created_at": utc_now(),
        }
        write_json(out_root / "JAIN_2017_CANONICAL_RUN_RECEIPT.json", final_receipt)
        return final_receipt

    except Exception as exc:
        text = str(exc)
        if "candidate" in text.lower() and ("mismatch" in text.lower() or "count" in text.lower()):
            reason = "SOURCE_COHORT_MISMATCH"
        elif "xlsx" in text.lower() or "source" in text.lower() or "artifact" in text.lower():
            reason = "SOURCE_BIND_FAILED"
        else:
            reason = "CANONICAL_PIPELINE_BLOCKED"
        blocked = _blocked_receipt(
            reason=reason,
            source_attestation=source_attestation,
            source_manifest=source_manifest,
            detail={"error_type": type(exc).__name__, "error": text},
        )
        write_json(out_root / "JAIN_2017_CANONICAL_RUN_RECEIPT.json", blocked)
        return blocked


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind manually acquired canonical Jain 2017 supplements and run frozen CPG-001 without network access."
    )
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        receipt = run_canonical_bind(args.source_dir, args.out_dir, args.attestation)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(receipt, indent=2, sort_keys=True))
    # Scientific negative verdicts are valid completed experiments, not CI failures.
    return 0 if receipt.get("execution_status") == "COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
