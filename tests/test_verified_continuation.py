from __future__ import annotations

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.verified_continuation import (
    DSM_PROJECTION_SCHEMA,
    LANE_IDS,
    VerifiedContinuationError,
    build_dsm_projection,
    build_experiment_summary,
    evaluate_continuation_trial,
    load_and_evaluate_trial,
    run_branch_authorization_trial,
    validate_lane_result,
    verify_branch_authorization_trial,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "benchmarks" / "verified_continuation"


def _fixture_values() -> tuple[dict, list[dict]]:
    spec = json.loads((FIXTURE / "trial_spec.json").read_text(encoding="utf-8"))
    lanes = [
        json.loads(
            (FIXTURE / "lanes" / f"{lane_id}.json").read_text(encoding="utf-8")
        )
        for lane_id in LANE_IDS
    ]
    return spec, lanes


def _json_paths(value: object, prefix: tuple[object, ...] = ()):
    yield prefix
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _json_paths(child, (*prefix, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _json_paths(child, (*prefix, index))


def _replace_json_path(
    value: object,
    path: tuple[object, ...],
    replacement: object,
) -> object:
    if not path:
        return copy.deepcopy(replacement)
    result = copy.deepcopy(value)
    cursor = result
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = copy.deepcopy(replacement)  # type: ignore[index]
    return result


def _half_life_fixture() -> tuple[Path, Path, Path] | None:
    root_value = os.environ.get("OLP_HALF_LIFE_ROOT")
    if not root_value:
        return None
    root = Path(root_value).resolve()
    output = root / "examples" / "demo_output"
    succession_key = root / "policy" / "succession_policy_public_key.hex"
    compaction_key = root / "policy" / "compaction_policy_public_key.hex"
    if not all(path.exists() for path in (output, succession_key, compaction_key)):
        return None
    try:
        import openline_half_life  # noqa: F401
    except ImportError:
        return None
    return output, succession_key, compaction_key


class VerifiedContinuationPureTests(unittest.TestCase):
    def test_synthetic_fixture_cannot_earn_continuation_claim(self) -> None:
        report = load_and_evaluate_trial(FIXTURE)
        self.assertTrue(report["controls"]["matched"])
        self.assertTrue(report["continuation_claim"]["mechanism_rule_passed"])
        self.assertEqual(
            report["continuation_claim"]["disposition"],
            "UNDECIDABLE",
        )
        self.assertFalse(
            report["continuation_claim"]["external_evidence_sufficient"]
        )

    def test_matched_external_results_can_pass_exact_frozen_rule(self) -> None:
        spec, lanes = _fixture_values()
        for lane in lanes:
            lane["evidence_class"] = "external_reproduction"
            lane["provider_execution_attested"] = True
        report = evaluate_continuation_trial(spec, lanes)
        self.assertEqual(report["continuation_claim"]["disposition"], "PASS")
        self.assertTrue(report["continuation_claim"]["olp_within_budget"])
        self.assertEqual(
            report["authorization_claim"]["disposition"],
            "NOT_EVALUATED",
        )

    def test_control_mismatch_is_invalid_not_a_bad_comparison(self) -> None:
        spec, lanes = _fixture_values()
        lanes[2]["controls"]["receiving_model"] = "fixture/different-model"
        report = evaluate_continuation_trial(spec, lanes)
        self.assertEqual(report["continuation_claim"]["disposition"], "INVALID")
        self.assertIn(
            "fixed_controls_mismatch",
            report["continuation_claim"]["reason_codes"],
        )

    def test_unknown_or_derived_fields_fail_closed(self) -> None:
        spec, lanes = _fixture_values()
        lane = copy.deepcopy(lanes[0])
        lane["reported_ucr"] = 1.0
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "lane_result_shape_invalid",
        ):
            validate_lane_result(lane, spec=spec)

    def test_discontinuous_trace_and_no_state_artifact_fail_closed(self) -> None:
        spec, lanes = _fixture_values()
        discontinuous = copy.deepcopy(lanes[0])
        discontinuous["trace"][1]["step"] = 8
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "trace_steps_not_contiguous",
        ):
            validate_lane_result(discontinuous, spec=spec)
        false_no_state = copy.deepcopy(lanes[1])
        false_no_state["inherited_state"]["artifact_sha256"] = "00" * 32
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "no_state_artifact_must_be_null",
        ):
            validate_lane_result(false_no_state, spec=spec)
        boolean_step = copy.deepcopy(lanes[0])
        boolean_step["trace"][0]["step"] = True
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "trace_steps_not_contiguous",
        ):
            validate_lane_result(boolean_step, spec=spec)
        boolean_protocol = copy.deepcopy(spec)
        boolean_protocol["protocol_version"] = True
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "trial_protocol_not_frozen_v1",
        ):
            evaluate_continuation_trial(boolean_protocol, lanes)
        changed_question = copy.deepcopy(spec)
        changed_question["question"] = "Can a changed trial certify itself?"
        with self.assertRaisesRegex(
            VerifiedContinuationError,
            "frozen_trial_spec_hash_mismatch",
        ):
            evaluate_continuation_trial(changed_question, lanes)

    def test_enum_fields_reject_every_non_string_json_type(self) -> None:
        spec, lanes = _fixture_values()
        invalid_values = (None, False, 0, 1.5, [], {})
        cases = (
            (
                "evidence_class",
                "lane_evidence_class_invalid",
                lambda lane, value: lane.__setitem__("evidence_class", value),
            ),
            (
                "trace_kind",
                "trace_kind_invalid",
                lambda lane, value: lane["trace"][0].__setitem__("kind", value),
            ),
            (
                "trace_status",
                "trace_status_invalid",
                lambda lane, value: lane["trace"][0].__setitem__("status", value),
            ),
            (
                "terminal_test_status",
                "terminal_test_status_invalid",
                lambda lane, value: lane["terminal_tests"][0].__setitem__(
                    "status",
                    value,
                ),
            ),
        )
        for field, expected_error, mutate in cases:
            for value in invalid_values:
                with self.subTest(field=field, value_type=type(value).__name__):
                    malformed = copy.deepcopy(lanes)
                    mutate(malformed[0], value)
                    with self.assertRaisesRegex(
                        VerifiedContinuationError,
                        expected_error,
                    ):
                        evaluate_continuation_trial(spec, malformed)

    def test_lane_collection_requires_a_real_sequence(self) -> None:
        spec, _ = _fixture_values()
        for value in (None, "lanes", b"lanes", bytearray(b"lanes")):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(
                    VerifiedContinuationError,
                    "lane_results_not_sequence",
                ):
                    evaluate_continuation_trial(spec, value)  # type: ignore[arg-type]

    def test_json_type_shape_fuzz_never_leaks_raw_exceptions(self) -> None:
        spec, lanes = _fixture_values()
        replacements = (
            None,
            False,
            True,
            -1,
            0,
            1,
            1.5,
            "",
            "x",
            "0" * 40,
            "0" * 64,
            [],
            [None],
            {},
            {"x": None},
        )
        leaks: list[str] = []
        probes = 0

        for path in _json_paths(spec):
            for replacement in replacements:
                candidate = _replace_json_path(spec, path, replacement)
                if candidate == spec:
                    continue
                probes += 1
                try:
                    evaluate_continuation_trial(candidate, lanes)  # type: ignore[arg-type]
                except VerifiedContinuationError:
                    pass
                except Exception as exc:  # pragma: no cover - asserted empty
                    leaks.append(
                        "spec:"
                        f"{path}:{type(replacement).__name__}:"
                        f"{type(exc).__name__}:{exc}"
                    )

        for lane_index, lane in enumerate(lanes):
            for path in _json_paths(lane):
                for replacement in replacements:
                    candidate_lanes = copy.deepcopy(lanes)
                    candidate_lanes[lane_index] = _replace_json_path(
                        lane,
                        path,
                        replacement,
                    )
                    if candidate_lanes[lane_index] == lane:
                        continue
                    probes += 1
                    try:
                        evaluate_continuation_trial(
                            spec,
                            candidate_lanes,  # type: ignore[arg-type]
                        )
                    except VerifiedContinuationError:
                        pass
                    except Exception as exc:  # pragma: no cover - asserted empty
                        leaks.append(
                            f"lane_{lane_index}:"
                            f"{path}:{type(replacement).__name__}:"
                            f"{type(exc).__name__}:{exc}"
                        )

        self.assertGreaterEqual(probes, 1774)
        self.assertEqual(leaks, [])

    def test_dsm_projection_is_display_only_and_does_not_invent_metrics(self) -> None:
        projection = build_dsm_projection(load_and_evaluate_trial(FIXTURE))
        self.assertEqual(projection["schema"], DSM_PROJECTION_SCHEMA)
        self.assertTrue(projection["display_only"])
        for metric in ("kappa", "phi_star", "vkd"):
            self.assertEqual(
                projection["coherence_dynamics"][metric]["status"],
                "UNDECIDABLE",
            )
        self.assertIn("must not", projection["grading_authority"])

    def test_authorization_and_continuation_cannot_mask_each_other(self) -> None:
        report = load_and_evaluate_trial(FIXTURE)
        summary = build_experiment_summary(
            report,
            {"passed": True, "report_hash": "11" * 32},
        )
        self.assertEqual(
            summary["disposition"],
            "READY_FOR_OUTSIDE_CONTINUATION_TRIAL",
        )
        self.assertEqual(
            summary["claims"]["continuation"]["disposition"],
            "UNDECIDABLE",
        )
        self.assertEqual(
            summary["claims"]["authorization"]["disposition"],
            "PASS",
        )


@unittest.skipUnless(
    _half_life_fixture() is not None,
    "Verified Continuation integration missing: install the pinned Half-Life "
    "fixture and set OLP_HALF_LIFE_ROOT",
)
class VerifiedContinuationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = _half_life_fixture()
        assert fixture is not None
        self.half_life_output, self.succession_key, self.compaction_key = fixture
        self.source_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("61" * 32))
        self.grader_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("62" * 32))
        self.gate_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("63" * 32))

    def run_trial(self, output: Path) -> dict:
        return run_branch_authorization_trial(
            self.half_life_output,
            output,
            succession_policy_public_key_path=self.succession_key,
            compaction_policy_public_key_path=self.compaction_key,
            source_signing_key=self.source_key,
            grader_signing_key=self.grader_key,
            gate_signing_key=self.gate_key,
            trial_id="verified-continuation-test",
        )

    def test_exact_branch_write_and_all_pre_effect_falsifiers(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="verified-continuation-test-"
        ) as temporary:
            result = self.run_trial(Path(temporary) / "output")
            self.assertTrue(result["passed"])
            self.assertTrue(result["wrong_branch_blocked"])
            self.assertTrue(result["mutated_target_blocked"])
            self.assertTrue(result["expired_blocked"])
            self.assertTrue(result["replay_blocked"])
            self.assertEqual(result["simultaneous_authorized"], 1)
            self.assertEqual(result["simultaneous_blocked"], 1)
            self.assertTrue(result["verification"]["valid"])

    def test_repository_bundle_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="verified-continuation-tamper-"
        ) as temporary:
            output = Path(temporary) / "output"
            result = self.run_trial(output)
            bundle = output / "authorized_repository.bundle"
            original = bundle.read_bytes()
            bundle.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
            verification = verify_branch_authorization_trial(
                output,
                trusted_gate_keys=[result["gate_public_key"]],
                half_life_output=self.half_life_output,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
            )
            self.assertFalse(verification["valid"])
            self.assertIn(
                "repository_bundle_hash_mismatch",
                verification["errors"],
            )
            bundle.write_bytes(original)
            request_path = output / "gate" / "gate_request.json"
            request = json.loads(request_path.read_text(encoding="utf-8"))
            request["commit_request"]["settings"]["new_commit"] = "00" * 20
            request_path.write_text(
                json.dumps(request, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            verification = verify_branch_authorization_trial(
                output,
                trusted_gate_keys=[result["gate_public_key"]],
                half_life_output=self.half_life_output,
                succession_policy_public_key_path=self.succession_key,
                compaction_policy_public_key_path=self.compaction_key,
            )
            self.assertFalse(verification["valid"])
            self.assertIn(
                "gate_commit_settings_hash_mismatch",
                verification["errors"],
            )


if __name__ == "__main__":
    unittest.main()
