from __future__ import annotations

import tempfile
import threading
import unittest
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from benchmarks.x402_airlock.fixture import (
    FIXED_NOW,
    SyntheticX402Fixture,
    clone,
    iso,
    set_path,
)
from olp_gate.verified_commit import VerifiedCommitLedger
from olp_gate.x402_airlock import (
    X402_RELEASE_RESULT_PROFILE,
    execute_x402_once,
)


class ExplodingMapping(Mapping[str, object]):
    def __getitem__(self, key: str) -> object:
        raise RuntimeError(f"hostile mapping access: {key}")

    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("hostile mapping iteration")

    def __len__(self) -> int:
        return 1


class X402TransactionAirlockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="x402-airlock-")
        self.root = Path(self.temp.name)
        self.fixture = SyntheticX402Fixture(self.root)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def execute(
        self,
        case: str,
        *,
        bundle: dict | None = None,
        attempted_action: dict | None = None,
        snapshot: dict | None = None,
        confirmation: dict | None = None,
        now=FIXED_NOW,
        settlement_calls: list[str] | None = None,
        release_calls: list[str] | None = None,
    ) -> dict:
        bundle = bundle or self.fixture.issue(case)
        action = attempted_action or bundle["action"]
        snapshot = snapshot or bundle["snapshot"]
        confirmation = confirmation or bundle["confirmation"]
        settlement_calls = (
            settlement_calls if settlement_calls is not None else []
        )
        release_calls = release_calls if release_calls is not None else []
        return execute_x402_once(
            VerifiedCommitLedger(self.root / f"{case}-commit-ledger.json"),
            bundle["receipt"],
            action,
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(snapshot),
            settlement_executor=lambda _settings: (
                settlement_calls.append(case)
                or {
                    "submitted": True,
                    "case": case,
                    "transaction_hash": confirmation[
                        "transaction_hash"
                    ],
                }
            ),
            confirmation_provider=lambda _result: clone(confirmation),
            release_executor=lambda request: (
                release_calls.append(case)
                or {
                    "profile": X402_RELEASE_RESULT_PROFILE,
                    "released": True,
                    "target": request["target"],
                    "transaction_hash": request["confirmation"][
                        "transaction_hash"
                    ],
                }
            ),
            now=now,
            attempt_label=case,
        )

    def test_clean_settlement_releases_only_after_confirmation(self) -> None:
        settlements: list[str] = []
        releases: list[str] = []
        result = self.execute(
            "clean",
            settlement_calls=settlements,
            release_calls=releases,
        )
        self.assertTrue(result["authorized"])
        self.assertTrue(result["settlement_confirmed"])
        self.assertTrue(result["resource_released"])
        self.assertEqual(settlements, ["clean"])
        self.assertEqual(releases, ["clean"])

    def test_live_clock_is_sampled_after_snapshot_provider(self) -> None:
        issued_at = datetime.now(timezone.utc)
        bundle = self.fixture.issue("live-clock", now=issued_at)

        def current_snapshot() -> dict:
            snapshot = clone(bundle["snapshot"])
            snapshot["checked_at"] = iso(datetime.now(timezone.utc))
            return snapshot

        result = execute_x402_once(
            VerifiedCommitLedger(self.root / "live-clock-ledger.json"),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=current_snapshot,
            settlement_executor=lambda _settings: {
                "transaction_hash": bundle["confirmation"][
                    "transaction_hash"
                ]
            },
            confirmation_provider=lambda _result: clone(
                bundle["confirmation"]
            ),
        )
        self.assertTrue(result["authorized"], result["reason_codes"])
        self.assertTrue(result["settlement_confirmed"])

    def test_exact_payment_mutations_are_blocked_before_state_or_effect(
        self,
    ) -> None:
        for index, (path, value) in enumerate(
            (
                ("settings.payment.network", "eip155:1"),
                (
                    "settings.payment.asset",
                    "eip155:8453/erc20:0x" + "aa" * 20,
                ),
                (
                    "settings.payment.recipient",
                    "0x" + "bb" * 20,
                ),
                ("settings.payment.amount_atomic", 100_001),
                ("settings.payment.scheme", "upto"),
            )
        ):
            with self.subTest(path=path):
                case = f"action-mutation-{index}"
                bundle = self.fixture.issue(case)
                attempted = clone(bundle["action"])
                set_path(attempted, path, value)
                snapshot_calls: list[bool] = []
                settlement_calls: list[bool] = []
                result = execute_x402_once(
                    VerifiedCommitLedger(
                        self.root / f"{case}-commit-ledger.json"
                    ),
                    bundle["receipt"],
                    attempted,
                    one_use_code=bundle["code"],
                    trusted_gate_keys=[bundle["gate_public_key"]],
                    snapshot_provider=lambda: (
                        snapshot_calls.append(True)
                        or clone(bundle["snapshot"])
                    ),
                    settlement_executor=lambda _settings: (
                        settlement_calls.append(True)
                        or {
                            "transaction_hash": bundle[
                                "confirmation"
                            ]["transaction_hash"]
                        }
                    ),
                    confirmation_provider=lambda _result: clone(
                        bundle["confirmation"]
                    ),
                    now=FIXED_NOW,
                )
                self.assertFalse(result["authorized"])
                self.assertIn("settings_mismatch", result["reason_codes"])
                self.assertEqual(snapshot_calls, [])
                self.assertEqual(settlement_calls, [])

    def test_invalid_issued_transactions_never_receive_permission(self) -> None:
        mutations = (
            (
                "scheme-mismatch",
                ("payment.scheme", "upto"),
                "x402_airlock:sr1_scheme_mismatch",
            ),
            (
                "network-mismatch",
                ("payment.network", "eip155:1"),
                "x402_airlock:sr1_network_mismatch",
            ),
            (
                "asset-mismatch",
                (
                    "payment.asset",
                    "eip155:8453/erc20:0x" + "aa" * 20,
                ),
                "x402_airlock:sr1_asset_mismatch",
            ),
            (
                "recipient-mismatch",
                ("payment.recipient", "0x" + "bb" * 20),
                "x402_airlock:sr1_recipient_mismatch",
            ),
            (
                "amount-mismatch",
                ("payment.amount_atomic", 100_001),
                "x402_airlock:sr1_amount_mismatch",
            ),
            (
                "zero-amount",
                ("payment.amount_atomic", 0),
                "x402_airlock:sr5_amount_not_positive",
            ),
            (
                "fee-over-cap",
                ("execution.fee_atomic", 10_001),
                "x402_airlock:sr6_fee_limit_exceeded",
            ),
            (
                "gas-over-cap",
                ("execution.gas", 200_001),
                "x402_airlock:sr6_gas_limit_exceeded",
            ),
            (
                "unexpected-instruction",
                (
                    "execution.instructions",
                    ["transferWithAuthorization", "attackerCall"],
                ),
                "x402_airlock:sr8_execution_template_not_allowed",
            ),
        )
        for case, mutation, expected_reason in mutations:
            with self.subTest(case=case):
                bundle = self.fixture.issue(
                    f"issue-{case}",
                    settings_mutation=mutation,
                )
                self.assertEqual(bundle["receipt"]["decision"], "DENY")
                self.assertIsNone(
                    bundle["receipt"]["commit_authorization"]
                )
                self.assertIn(
                    f"verified_commit:{expected_reason}",
                    bundle["receipt"]["reason_codes"],
                )

    def test_expired_payment_is_denied_at_receipt_issue(self) -> None:
        bundle = self.fixture.issue(
            "proof-expired",
            settings_mutation=(
                "payment.valid_before",
                iso(FIXED_NOW - timedelta(seconds=1)),
            ),
        )
        self.assertEqual(bundle["receipt"]["decision"], "DENY")
        self.assertIn(
            "verified_commit:x402_airlock:sr3_authorization_expired",
            bundle["receipt"]["reason_codes"],
        )

    def test_expired_commit_permission_blocks_before_snapshot(self) -> None:
        bundle = self.fixture.issue("permission-expired")
        snapshots: list[bool] = []
        settlements: list[bool] = []
        result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "permission-expired-ledger.json"
            ),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: (
                snapshots.append(True) or clone(bundle["snapshot"])
            ),
            settlement_executor=lambda _settings: (
                settlements.append(True)
                or {
                    "transaction_hash": bundle["confirmation"][
                        "transaction_hash"
                    ]
                }
            ),
            confirmation_provider=lambda _result: clone(
                bundle["confirmation"]
            ),
            now=bundle["expiry"],
        )
        self.assertFalse(result["authorized"])
        self.assertIn("authorization_expired", result["reason_codes"])
        self.assertEqual(snapshots, [])
        self.assertEqual(settlements, [])

    def test_fresh_receiver_state_failures_block_and_consume_permission(
        self,
    ) -> None:
        mutations = (
            (
                "authenticity",
                ("authorization_authentic", False),
                "sr2_authorization_not_authentic",
            ),
            (
                "authorization-hash",
                ("authorization_hash", "00" * 32),
                "sr2_authorization_hash_mismatch",
            ),
            (
                "nonce",
                ("nonce_unused", False),
                "sr5_nonce_already_used",
            ),
            (
                "balance",
                ("payer_balance_atomic", 99_999),
                "sr5_insufficient_balance",
            ),
            (
                "settleability",
                ("settleable", False),
                "sr5_payment_not_settleable",
            ),
            (
                "verification-context",
                ("verification_context_hash", "00" * 32),
                "sr7_verification_context_diverged",
            ),
            (
                "payment-context",
                ("payment_hash", "00" * 32),
                "sr7_payment_context_diverged",
            ),
        )
        for case, mutation, expected_reason in mutations:
            with self.subTest(case=case):
                bundle = self.fixture.issue(f"snapshot-{case}")
                snapshot = clone(bundle["snapshot"])
                set_path(snapshot, *mutation)
                settlements: list[bool] = []
                result = self.execute(
                    f"snapshot-{case}",
                    bundle=bundle,
                    snapshot=snapshot,
                    settlement_calls=settlements,
                )
                self.assertFalse(result["authorized"])
                self.assertTrue(result["permission_consumed"])
                self.assertIn(expected_reason, result["reason_codes"])
                self.assertEqual(settlements, [])

                retry = self.execute(
                    f"snapshot-{case}",
                    bundle=bundle,
                    snapshot=bundle["snapshot"],
                    settlement_calls=settlements,
                )
                self.assertFalse(retry["authorized"])
                self.assertIn(
                    "authorization_replay", retry["reason_codes"]
                )
                self.assertEqual(settlements, [])

    def test_stale_snapshot_blocks_before_settlement(self) -> None:
        bundle = self.fixture.issue("stale-snapshot")
        snapshot = clone(bundle["snapshot"])
        snapshot["checked_at"] = iso(FIXED_NOW - timedelta(seconds=6))
        result = self.execute(
            "stale-snapshot",
            bundle=bundle,
            snapshot=snapshot,
        )
        self.assertFalse(result["authorized"])
        self.assertIn(
            "sr7_receiver_snapshot_stale", result["reason_codes"]
        )
        self.assertFalse(result["settlement_executed"])

    def test_preflight_provider_error_fails_closed_and_consumes(self) -> None:
        bundle = self.fixture.issue("snapshot-error")
        settlements: list[bool] = []
        result = execute_x402_once(
            VerifiedCommitLedger(self.root / "snapshot-error-ledger.json"),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: (_ for _ in ()).throw(
                RuntimeError("receiver unavailable")
            ),
            settlement_executor=lambda _settings: (
                settlements.append(True) or {}
            ),
            confirmation_provider=lambda _result: clone(
                bundle["confirmation"]
            ),
            now=FIXED_NOW,
        )
        self.assertFalse(result["authorized"])
        self.assertTrue(result["permission_consumed"])
        self.assertIn(
            "receiver_preflight_error:RuntimeError",
            result["reason_codes"],
        )
        self.assertEqual(settlements, [])

    def test_generic_verified_commit_cannot_bypass_x402_preflight(self) -> None:
        bundle = self.fixture.issue("generic-bypass")
        calls: list[bool] = []
        result = VerifiedCommitLedger(
            self.root / "generic-bypass-ledger.json"
        ).execute_once(
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            executor=lambda: calls.append(True),
            now=FIXED_NOW,
        )
        self.assertFalse(result["authorized"])
        self.assertTrue(result["permission_consumed"])
        self.assertIn(
            "receiver_preflight_required", result["reason_codes"]
        )
        self.assertEqual(calls, [])

    def test_unconfirmed_or_mismatched_settlement_never_releases(
        self,
    ) -> None:
        for case, mutation, expected in (
            (
                "unconfirmed",
                ("confirmed", False),
                "sr4_settlement_not_confirmed",
            ),
            (
                "wrong-recipient",
                ("recipient", "0x" + "bb" * 20),
                "sr4_settlement_recipient_mismatch",
            ),
            (
                "wrong-network",
                ("network", "eip155:1"),
                "sr4_settlement_network_mismatch",
            ),
        ):
            with self.subTest(case=case):
                bundle = self.fixture.issue(f"confirmation-{case}")
                confirmation = clone(bundle["confirmation"])
                set_path(confirmation, *mutation)
                settlements: list[str] = []
                releases: list[str] = []
                result = self.execute(
                    f"confirmation-{case}",
                    bundle=bundle,
                    confirmation=confirmation,
                    settlement_calls=settlements,
                    release_calls=releases,
                )
                self.assertTrue(result["authorized"])
                self.assertTrue(result["settlement_executed"])
                self.assertFalse(result["settlement_confirmed"])
                self.assertFalse(result["resource_released"])
                self.assertIn(expected, result["reason_codes"])
                self.assertEqual(len(settlements), 1)
                self.assertEqual(releases, [])

    def test_replay_never_settles_twice(self) -> None:
        bundle = self.fixture.issue("replay")
        settlements: list[str] = []
        releases: list[str] = []
        first = self.execute(
            "replay",
            bundle=bundle,
            settlement_calls=settlements,
            release_calls=releases,
        )
        second = self.execute(
            "replay",
            bundle=bundle,
            settlement_calls=settlements,
            release_calls=releases,
        )
        self.assertTrue(first["authorized"])
        self.assertFalse(second["authorized"])
        self.assertIn("authorization_replay", second["reason_codes"])
        self.assertEqual(len(settlements), 1)
        self.assertEqual(len(releases), 1)

    def test_two_simultaneous_uses_settle_exactly_once(self) -> None:
        bundle = self.fixture.issue("concurrent")
        ledger = VerifiedCommitLedger(self.root / "concurrent-ledger.json")
        barrier = threading.Barrier(2)
        settlements: list[int] = []
        releases: list[int] = []

        def use(index: int) -> dict:
            barrier.wait()
            return execute_x402_once(
                ledger,
                bundle["receipt"],
                bundle["action"],
                one_use_code=bundle["code"],
                trusted_gate_keys=[bundle["gate_public_key"]],
                snapshot_provider=lambda: clone(bundle["snapshot"]),
                settlement_executor=lambda _settings: (
                    settlements.append(index)
                    or {
                        "index": index,
                        "transaction_hash": bundle["confirmation"][
                            "transaction_hash"
                        ],
                    }
                ),
                confirmation_provider=lambda _result: clone(
                    bundle["confirmation"]
                ),
                release_executor=lambda request: (
                    releases.append(index)
                    or {
                        "profile": X402_RELEASE_RESULT_PROFILE,
                        "released": True,
                        "target": request["target"],
                        "transaction_hash": request["confirmation"][
                            "transaction_hash"
                        ],
                    }
                ),
                now=FIXED_NOW,
                attempt_label=f"concurrent-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(use, (1, 2)))
        self.assertEqual(sum(item["authorized"] for item in results), 1)
        self.assertEqual(len(settlements), 1)
        self.assertEqual(len(releases), 1)
        blocked = next(item for item in results if not item["authorized"])
        self.assertIn("authorization_replay", blocked["reason_codes"])

    def test_distinct_commit_receipts_share_atomic_payment_nonce_scope(
        self,
    ) -> None:
        bundles = [
            self.fixture.issue("distinct-nonce-race-a"),
            self.fixture.issue("distinct-nonce-race-b"),
        ]
        ledger = VerifiedCommitLedger(
            self.root / "distinct-nonce-race-ledger.json"
        )
        barrier = threading.Barrier(2)
        snapshots: list[int] = []
        settlements: list[int] = []
        releases: list[int] = []

        def use(index: int) -> dict:
            bundle = bundles[index]
            barrier.wait()
            return execute_x402_once(
                ledger,
                bundle["receipt"],
                bundle["action"],
                one_use_code=bundle["code"],
                trusted_gate_keys=[bundle["gate_public_key"]],
                snapshot_provider=lambda: (
                    snapshots.append(index)
                    or clone(bundle["snapshot"])
                ),
                settlement_executor=lambda _settings: (
                    settlements.append(index)
                    or {
                        "transaction_hash": bundle["confirmation"][
                            "transaction_hash"
                        ]
                    }
                ),
                confirmation_provider=lambda _result: clone(
                    bundle["confirmation"]
                ),
                release_executor=lambda request: (
                    releases.append(index)
                    or {
                        "profile": X402_RELEASE_RESULT_PROFILE,
                        "released": True,
                        "target": request["target"],
                        "transaction_hash": request["confirmation"][
                            "transaction_hash"
                        ],
                    }
                ),
                now=FIXED_NOW,
                attempt_label=f"distinct-nonce-race-{index}",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(use, (0, 1)))
        self.assertEqual(sum(item["authorized"] for item in results), 1)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(len(settlements), 1)
        self.assertEqual(len(releases), 1)
        self.assertEqual(
            sum(item["resource_released"] for item in results),
            1,
        )
        blocked = next(item for item in results if not item["authorized"])
        self.assertIn("replay_scope_reused", blocked["reason_codes"])

    def test_unknown_nested_fields_fail_closed_at_issue(self) -> None:
        bundle = self.fixture.issue(
            "unknown-field",
            settings_mutation=("execution.attacker_calldata", "0xdeadbeef"),
        )
        self.assertEqual(bundle["receipt"]["decision"], "DENY")
        self.assertIn(
            (
                "verified_commit:x402_airlock:"
                "x402_execution_shape_invalid"
            ),
            bundle["receipt"]["reason_codes"],
        )

    def test_confirmation_must_name_submitted_transaction(self) -> None:
        bundle = self.fixture.issue("transaction-hash-divergence")
        settlements: list[bool] = []
        releases: list[bool] = []
        result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "transaction-hash-divergence-ledger.json"
            ),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(bundle["snapshot"]),
            settlement_executor=lambda _settings: (
                settlements.append(True)
                or {
                    "transaction_hash": "aa" * 32,
                }
            ),
            confirmation_provider=lambda _result: clone(
                bundle["confirmation"]
            ),
            release_executor=lambda _confirmation: releases.append(True),
            now=FIXED_NOW,
        )
        self.assertTrue(result["authorized"])
        self.assertFalse(result["settlement_confirmed"])
        self.assertFalse(result["resource_released"])
        self.assertIn(
            "sr4_settlement_transaction_hash_mismatch",
            result["reason_codes"],
        )
        self.assertEqual(settlements, [True])
        self.assertEqual(releases, [])

    def test_release_callback_requires_exact_positive_acknowledgment(
        self,
    ) -> None:
        for case, release_value, expected_reason in (
            (
                "release-false",
                {
                    "profile": X402_RELEASE_RESULT_PROFILE,
                    "released": False,
                    "target": "resource://weather-report/42",
                    "transaction_hash": None,
                },
                "resource_release_not_confirmed",
            ),
            (
                "release-wrong-target",
                {
                    "profile": X402_RELEASE_RESULT_PROFILE,
                    "released": True,
                    "target": "resource://weather-report/attacker",
                    "transaction_hash": None,
                },
                "resource_release_target_mismatch",
            ),
            (
                "release-noncanonical-extra",
                {
                    "profile": X402_RELEASE_RESULT_PROFILE,
                    "released": True,
                    "target": "resource://weather-report/42",
                    "transaction_hash": None,
                    "attacker": object(),
                },
                "resource_release_result_shape_invalid",
            ),
        ):
            with self.subTest(case=case):
                bundle = self.fixture.issue(case)
                value = clone(release_value)
                value["transaction_hash"] = bundle["confirmation"][
                    "transaction_hash"
                ]
                result = execute_x402_once(
                    VerifiedCommitLedger(
                        self.root / f"{case}-commit-ledger.json"
                    ),
                    bundle["receipt"],
                    bundle["action"],
                    one_use_code=bundle["code"],
                    trusted_gate_keys=[bundle["gate_public_key"]],
                    snapshot_provider=lambda: clone(bundle["snapshot"]),
                    settlement_executor=lambda _settings: {
                        "transaction_hash": bundle["confirmation"][
                            "transaction_hash"
                        ]
                    },
                    confirmation_provider=lambda _result: clone(
                        bundle["confirmation"]
                    ),
                    release_executor=lambda _request: clone(value),
                    now=FIXED_NOW,
                )
                self.assertTrue(result["authorized"])
                self.assertTrue(result["settlement_confirmed"])
                self.assertFalse(result["resource_released"])
                self.assertIn(expected_reason, result["reason_codes"])

        bundle = self.fixture.issue("release-error")
        result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "release-error-commit-ledger.json"
            ),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(bundle["snapshot"]),
            settlement_executor=lambda _settings: {
                "transaction_hash": bundle["confirmation"][
                    "transaction_hash"
                ]
            },
            confirmation_provider=lambda _result: clone(
                bundle["confirmation"]
            ),
            release_executor=lambda _request: (_ for _ in ()).throw(
                RuntimeError("release unavailable")
            ),
            now=FIXED_NOW,
        )
        self.assertTrue(result["authorized"])
        self.assertTrue(result["settlement_confirmed"])
        self.assertFalse(result["resource_released"])
        self.assertIn(
            "resource_release_error:RuntimeError",
            result["reason_codes"],
        )

        exploding_bundle = self.fixture.issue("release-exploding-mapping")
        exploding_result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "release-exploding-ledger.json"
            ),
            exploding_bundle["receipt"],
            exploding_bundle["action"],
            one_use_code=exploding_bundle["code"],
            trusted_gate_keys=[exploding_bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(
                exploding_bundle["snapshot"]
            ),
            settlement_executor=lambda _settings: {
                "transaction_hash": exploding_bundle["confirmation"][
                    "transaction_hash"
                ]
            },
            confirmation_provider=lambda _result: clone(
                exploding_bundle["confirmation"]
            ),
            release_executor=lambda _request: ExplodingMapping(),
            now=FIXED_NOW,
        )
        self.assertTrue(exploding_result["authorized"])
        self.assertTrue(exploding_result["settlement_confirmed"])
        self.assertFalse(exploding_result["resource_released"])
        self.assertIn(
            "resource_release_error:RuntimeError",
            exploding_result["reason_codes"],
        )

    def test_noncanonical_confirmation_fails_closed_without_crashing(
        self,
    ) -> None:
        bundle = self.fixture.issue("confirmation-noncanonical-extra")
        confirmation = clone(bundle["confirmation"])
        confirmation["attacker"] = object()
        releases: list[bool] = []
        result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "confirmation-noncanonical-ledger.json"
            ),
            bundle["receipt"],
            bundle["action"],
            one_use_code=bundle["code"],
            trusted_gate_keys=[bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(bundle["snapshot"]),
            settlement_executor=lambda _settings: {
                "transaction_hash": bundle["confirmation"][
                    "transaction_hash"
                ]
            },
            confirmation_provider=lambda _result: confirmation,
            release_executor=lambda _request: releases.append(True),
            now=FIXED_NOW,
        )
        self.assertTrue(result["authorized"])
        self.assertFalse(result["settlement_confirmed"])
        self.assertFalse(result["resource_released"])
        self.assertIn(
            "sr4_settlement_confirmation_shape_invalid",
            result["reason_codes"],
        )
        self.assertEqual(releases, [])

        exploding_bundle = self.fixture.issue(
            "confirmation-exploding-mapping"
        )
        exploding_result = execute_x402_once(
            VerifiedCommitLedger(
                self.root / "confirmation-exploding-ledger.json"
            ),
            exploding_bundle["receipt"],
            exploding_bundle["action"],
            one_use_code=exploding_bundle["code"],
            trusted_gate_keys=[exploding_bundle["gate_public_key"]],
            snapshot_provider=lambda: clone(
                exploding_bundle["snapshot"]
            ),
            settlement_executor=lambda _settings: {
                "transaction_hash": exploding_bundle["confirmation"][
                    "transaction_hash"
                ]
            },
            confirmation_provider=lambda _result: ExplodingMapping(),
            now=FIXED_NOW,
        )
        self.assertTrue(exploding_result["authorized"])
        self.assertFalse(exploding_result["settlement_confirmed"])
        self.assertIn(
            "sr4_confirmation_provider_error:RuntimeError",
            exploding_result["reason_codes"],
        )


if __name__ == "__main__":
    unittest.main()
