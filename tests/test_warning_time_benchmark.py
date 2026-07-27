from __future__ import annotations

import inspect
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from benchmarks.warning_time.calibration import (
    CALIBRATION_EVIDENCE_PATH,
    CALIBRATION_PROFILE_PATH,
    FREEZE_ANCHOR_PATH,
    FREEZE_PUBLICATION_PATH,
    ROOT,
    SCENARIO_PATH,
    THRESHOLDS_PATH,
    build_calibration_evidence,
    calibrate_thresholds,
    load_json,
    validate_seed_partition,
    verify_external_anchor,
    verify_profile,
    verify_publication,
)
from benchmarks.warning_time.metric_proxies import metrics_for_observation
from benchmarks.warning_time.run_benchmark import (
    CASES,
    GATE_KEY,
    build_trajectory,
    label_leak_probe,
    run_benchmark,
)
from olp_gate.crypto import public_key_hex, sign_olp_body, verify_olp_signature
from olp_gate.gateway import verify_decision_log


class WarningTimeBenchmarkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scenario = load_json(SCENARIO_PATH)
        self.evidence = load_json(CALIBRATION_EVIDENCE_PATH)
        self.thresholds = load_json(THRESHOLDS_PATH)
        self.profile = load_json(CALIBRATION_PROFILE_PATH)
        self.publication = load_json(FREEZE_PUBLICATION_PATH)
        self.anchor = load_json(FREEZE_ANCHOR_PATH)

    def test_calibration_is_disjoint_and_heldout_seeds_are_paired(self) -> None:
        validate_seed_partition(self.scenario)
        calibration = set(self.scenario["calibration_seeds"])
        paired = self.scenario["heldout_seeds"]["control"]
        for case in CASES:
            self.assertEqual(self.scenario["heldout_seeds"][case], paired)
            self.assertFalse(calibration & set(self.scenario["heldout_seeds"][case]))
        self.assertTrue(self.scenario["paired_heldout_design"])

    def test_clean_calibration_and_thresholds_reproduce_without_heldout_data(self) -> None:
        expected_evidence = build_calibration_evidence(self.scenario)
        expected_thresholds = calibrate_thresholds(self.scenario, expected_evidence)
        self.assertEqual(expected_evidence, self.evidence)
        self.assertEqual(expected_thresholds, self.thresholds)
        self.assertFalse(self.evidence["corrupted_runs_used"])
        self.assertFalse(self.evidence["heldout_runs_used"])
        self.assertEqual(self.evidence["run_count"], 40)
        for run in self.evidence["runs"]:
            for row in run["trace"]:
                features = row["observable_features"]
                self.assertEqual(features["missing_required_evidence"], 0)
                self.assertEqual(features["orphaned_material_references"], 0)
                self.assertEqual(features["unflagged_constraint_conflicts"], 0)
                self.assertEqual(features["evidence_edges_lost"], 0)

    def test_profile_publication_and_external_anchor_verify(self) -> None:
        self.assertTrue(verify_profile(
            self.profile, self.scenario, self.evidence, self.thresholds
        )["valid"])
        self.assertTrue(verify_publication(
            self.publication, self.profile, self.evidence, self.thresholds
        )["valid"])
        self.assertTrue(verify_external_anchor(
            self.anchor,
            self.publication,
            self.profile,
            self.thresholds,
            self.evidence,
        )["valid"])
        for artifact in (self.profile, self.publication, self.anchor):
            valid, error = verify_olp_signature(artifact)
            self.assertTrue(valid, error)
        self.assertEqual(self.anchor["anchor_type"], "private_external_custody")
        self.assertFalse(self.anchor["private_witness_key_distributed"])

    def test_external_anchor_cannot_choose_its_own_witness(self) -> None:
        body = dict(self.anchor)
        body.pop("signature")
        body.pop("payload_hash")
        body["anchored_at"] = "2026-07-27T02:05:27Z"
        substituted = sign_olp_body(
            body,
            Ed25519PrivateKey.from_private_bytes(bytes.fromhex("71" * 32)),
        )
        result = verify_external_anchor(
            substituted,
            self.publication,
            self.profile,
            self.thresholds,
            self.evidence,
        )
        self.assertFalse(result["valid"])
        self.assertIn("external_anchor_signer_key_mismatch", result["errors"])
        self.assertIn("external_anchor_payload_not_receiver_approved", result["errors"])

    def test_profile_freshness_rejects_future_and_expired_profiles(self) -> None:
        future = json.loads(json.dumps(self.profile))
        future["created_at"] = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat().replace("+00:00", "Z")
        result = verify_profile(future, self.scenario, self.evidence, self.thresholds)
        self.assertIn("payload_hash_mismatch", result["errors"])
        self.assertIn("profile_created_at_in_future", result["errors"])

        expired_now = datetime.fromisoformat(
            self.profile["expires_at"].replace("Z", "+00:00")
        ) + timedelta(seconds=1)
        result = verify_profile(
            self.profile,
            self.scenario,
            self.evidence,
            self.thresholds,
            now=expired_now,
        )
        self.assertIn("profile_expired", result["errors"])

    def test_metric_function_has_no_ground_truth_or_case_parameter(self) -> None:
        parameters = list(inspect.signature(metrics_for_observation).parameters)
        self.assertEqual(
            parameters,
            ["seed", "step", "observation", "previous_observation"],
        )
        forbidden = {"case", "corruption", "injection_step", "bad_action"}
        self.assertFalse(set(parameters) & forbidden)

    def test_label_swap_probe_uses_same_seed_and_follows_state_not_label(self) -> None:
        probe = label_leak_probe(self.scenario, self.thresholds)
        self.assertTrue(probe["passed"], probe)
        self.assertIsNone(probe["clean_state_with_corrupt_display_label_first_warning"])
        self.assertIsNotNone(probe["corrupt_state_with_control_display_label_first_warning"])
        self.assertTrue(probe["pre_injection_observations_and_metrics_identical"])
        self.assertEqual(probe["forbidden_metric_parameters"], [])

    def test_paired_runs_match_control_before_injection(self) -> None:
        seed = self.scenario["heldout_seeds"]["control"][0]
        control = build_trajectory("control", self.scenario, self.thresholds, seed=seed)
        for case in ("dropped_counterevidence", "unflagged_contradiction"):
            injected = build_trajectory(case, self.scenario, self.thresholds, seed=seed)
            for index in range(self.scenario["injection_step"] - 1):
                self.assertEqual(control[index]["metrics"], injected[index]["metrics"])
                self.assertEqual(
                    control[index]["observable_state"],
                    injected[index]["observable_state"],
                )

    def test_warning_time_is_bad_action_minus_first_warning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = run_benchmark(Path(temporary) / "results")
        for case in ("dropped_counterevidence", "unflagged_contradiction"):
            item = report["reference_cases"][case]
            self.assertEqual(
                item["warning_time_steps"],
                item["bad_action_step"] - item["first_warning_step"],
            )
            self.assertGreater(item["warning_time_steps"], 0)

    def test_heldout_counts_decisions_and_enforcement_are_separate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "results"
            report = run_benchmark(out)
            rows = [json.loads(line) for line in (out / "heldout_results.jsonl").read_text().splitlines()]
        aggregate = report["aggregate"]
        self.assertEqual(len(rows), 60)
        self.assertEqual(report["heldout"]["total_runs"], 100)
        self.assertEqual(aggregate["heldout_clean_runs_evaluated"], 20)
        self.assertEqual(aggregate["heldout_clean_run_false_alarms"], 0)
        self.assertEqual(aggregate["heldout_corruption_runs"], 40)
        self.assertEqual(aggregate["missed_corruptions"], 0)
        self.assertEqual(aggregate["no_advance_warning_corruptions"], 0)
        self.assertEqual(aggregate["prevented_bad_actions_in_enforcement"], 40)
        self.assertEqual(aggregate["final_decision_counts"], {
            "control": {"COMMIT": 20},
            "dropped_counterevidence": {"QUARANTINE": 20},
            "unflagged_contradiction": {"DENY": 20},
        })

    def test_reference_decision_logs_are_signed_and_chain_verify(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "results"
            run_benchmark(out)
            for case in CASES:
                result = verify_decision_log(
                    out / case / "decision_receipts.jsonl",
                    [public_key_hex(GATE_KEY)],
                )
                self.assertTrue(result["valid"], result)

    def test_independent_verifier_does_not_import_benchmark_modules(self) -> None:
        verifier = Path(__file__).resolve().parents[1] / "scripts" / "verify_warning_time_benchmark.py"
        source = verifier.read_text(encoding="utf-8")
        self.assertNotIn("from benchmarks.warning_time", source)
        completed = subprocess.run(
            [sys.executable, str(verifier)],
            cwd=verifier.parents[1],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        result = json.loads(completed.stdout)
        self.assertTrue(result["valid"], result)
        self.assertTrue(result["independent_of_benchmark_modules"])
        self.assertTrue(result["paired_heldout_seeds"])

    def test_frozen_decision_logs_are_present_and_not_gitignored(self) -> None:
        results = ROOT / "results"
        report = load_json(results / "benchmark_report.json")
        expected = [
            f"{case}/decision_receipts.jsonl"
            for case in CASES
        ]
        self.assertTrue(set(expected).issubset(report["artifact_hashes"]))
        for relative in expected:
            self.assertTrue((results / relative).is_file(), relative)

        git = shutil.which("git")
        self.assertIsNotNone(git, "git is required for the release source-closure test")
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            initialized = subprocess.run(
                [str(git), "init", "-q"],
                cwd=checkout,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            (checkout / ".gitignore").write_text(
                (ROOT.parent.parent / ".gitignore").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            for relative in expected:
                path = checkout / "benchmarks" / "warning_time" / "results" / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{}\n", encoding="utf-8")
                ignored = subprocess.run(
                    [
                        str(git),
                        "-c",
                        "core.excludesFile=/dev/null",
                        "check-ignore",
                        "--no-index",
                        "--quiet",
                        "--",
                        str(path.relative_to(checkout)),
                    ],
                    cwd=checkout,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    ignored.returncode,
                    1,
                    f"{relative} is still excluded by .gitignore",
                )


if __name__ == "__main__":
    unittest.main()
