#!/usr/bin/env python3
"""Preserve two real process-death failures of the pre-adapter dual write.

Run from the repository root:
  python experiments/openline-consequence-002/reproduce_dual_write.py \
    > experiments/openline-consequence-002/evidence/before/raw.log 2>&1

Exit 1 and two FAILED assertions are the expected NEGATIVE result. This script
uses the existing test issuer solely to construct a genuinely signed COMMIT;
all execution uses the unchanged production VerifiedCommitLedger. No adapter
is imported. Fixture keys and one-use code are public test material.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from olp_gate.gateway import verify_decision_receipt
from olp_gate.verified_commit import VerifiedCommitLedger

BEFORE = Path(os.environ.get("CONSEQUENCE_NEGATIVE_OUTPUT") or tempfile.mkdtemp(prefix="consequence-002-negative-"))


def write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def worker(case: str, directory: Path) -> None:
    fixture = json.loads((BEFORE / "signed-fixture.json").read_text())

    def execute() -> dict:
        if case == "after_json_spend_before_sqlite":
            os._exit(73)  # genuine process death; no exception/finally handlers
        connection = sqlite3.connect(directory / "state.sqlite3")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("UPDATE commissioning SET commissioned=1 WHERE id='local-fixture'")
        connection.commit()
        os._exit(74)  # SQLite committed; JSON execution completion not recorded

    result = VerifiedCommitLedger(directory / "ledger.json").execute_once(
        fixture["receipt"], fixture["action"],
        one_use_code=fixture["one_use_code"],
        trusted_gate_keys=[fixture["gate_public_key"]],
        executor=execute, attempt_label=case,
    )
    print(json.dumps(result), flush=True)
    raise RuntimeError("crash point was not reached")


def main() -> int:
    os.environ["CONSEQUENCE_NEGATIVE_OUTPUT"] = str(BEFORE.resolve())
    if (BEFORE / "negative-result.json").exists():
        raise FileExistsError("refusing to overwrite preserved negative evidence")
    BEFORE.mkdir(parents=True, exist_ok=True)
    # Import only the pre-existing fixture issuer; invoke no test assertions.
    spec = importlib.util.spec_from_file_location("original_verified_commit_fixture", ROOT / "tests/test_verified_commit.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    issuer = module.VerifiedCommitTests()
    issuer.setUp()
    try:
        receipt, action, code, _expiry = issuer.issue("consequence-002-negative")
        fixture = {"receipt": receipt, "action": action, "one_use_code": code,
                   "gate_public_key": issuer.gate_public_key,
                   "warning": "PUBLIC TEST FIXTURE; no real capability, device, or packet enforcement"}
    finally:
        issuer.tearDown()
    assert verify_decision_receipt(receipt, [fixture["gate_public_key"]])["valid"]
    write(BEFORE / "signed-fixture.json", fixture)
    originals = ["olp_gate/verified_commit.py", "olp_gate/subject_bound_commit.py",
                 "olp_gate/evidence.py", "tests/test_verified_commit.py"]
    write(BEFORE / "source-and-fixture-hashes.json", {
        "git_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "original_files_sha256": {name: digest(ROOT / name) for name in originals},
        "fixture_file_sha256": digest(BEFORE / "signed-fixture.json"),
        "signed_decision_payload_hash": receipt["payload_hash"],
        "authorization_hash": receipt["commit_authorization"]["authorization_hash"],
        "action_hash": receipt["commit_authorization"]["action_hash"],
        "receipt_signature_verified": True,
        "command": "python experiments/openline-consequence-002/reproduce_dual_write.py > experiments/openline-consequence-002/evidence/before/raw.log 2>&1",
        "expected_exit_status": 1,
    })
    observations = {}
    for case, crash_code in [("after_json_spend_before_sqlite", 73), ("after_sqlite_commit_before_json_completion", 74)]:
        directory = BEFORE / case
        directory.mkdir(exist_ok=True)
        # This is a dedicated reproduction output; preserve original code.
        for filename in ("state.sqlite3", "ledger.json", "ledger.json.lock"):
            (directory / filename).unlink(missing_ok=True)
        with sqlite3.connect(directory / "state.sqlite3") as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("CREATE TABLE commissioning(id TEXT PRIMARY KEY, commissioned INTEGER NOT NULL CHECK(commissioned IN (0,1)))")
            connection.execute("INSERT INTO commissioning VALUES ('local-fixture', 0)")
        completed = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", case, str(directory)], cwd=ROOT, capture_output=True, text=True)
        assert completed.returncode == crash_code, (case, completed.returncode, completed.stdout, completed.stderr)
        state = json.loads((directory / "ledger.json").read_text())
        with sqlite3.connect(directory / "state.sqlite3") as connection:
            rows = connection.execute("SELECT id, commissioned FROM commissioning ORDER BY id").fetchall()
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        # A fresh object models restart and proves permission is durably spent.
        restart = VerifiedCommitLedger(directory / "ledger.json").check_and_consume(
            receipt, action, one_use_code=code,
            trusted_gate_keys=[fixture["gate_public_key"]], attempt_label="restart-retry")
        observation = {
            "child_exit_status": completed.returncode,
            "child_stdout": completed.stdout, "child_stderr": completed.stderr,
            "sqlite_rows_after_crash": rows, "sqlite_integrity": integrity,
            "ledger_after_crash": state,
            "restart_retry": restart,
            "authorization_consumed": receipt["payload_hash"] in state["consumed_decisions"],
            "completed_outcomes": [item for item in state["attempts"] if item["execution_status"] == "completed"],
            "sqlite_file_sha256": digest(directory / "state.sqlite3"),
        }
        write(directory / "observed.json", observation)
        observations[case] = observation
        print(json.dumps({"case": case, "child_exit_status": completed.returncode,
                          "sqlite_rows": rows, "authorization_consumed": observation["authorization_consumed"],
                          "execution_status": state["attempts"][0]["execution_status"],
                          "restart_authorized": restart["authorized"], "restart_reasons": restart["reason_codes"]}), flush=True)

    class AtomicConsequenceContract(unittest.TestCase):
        def test_crash_before_mutation_must_not_consume_authorization(self):
            observed = observations["after_json_spend_before_sqlite"]
            self.assertEqual(observed["sqlite_rows_after_crash"][0][1], 0)
            self.assertFalse(observed["authorization_consumed"], "ATOMICITY FALSIFIED: permission durably consumed while SQLite protected mutation is absent")

        def test_committed_mutation_must_have_durable_completed_outcome(self):
            observed = observations["after_sqlite_commit_before_json_completion"]
            self.assertEqual(observed["sqlite_rows_after_crash"][0][1], 1)
            self.assertTrue(observed["authorization_consumed"])
            self.assertEqual(len(observed["completed_outcomes"]), 1, "OUTCOME CONTINUITY FALSIFIED: SQLite effect committed with no durable completed outcome in authorization ledger")

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AtomicConsequenceContract))
    write(BEFORE / "negative-result.json", {
        "classification": "NEGATIVE: EXISTING JSON/SQLITE DUAL WRITE IS NOT ATOMIC",
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "failure_reports": [{"test": str(test), "traceback": report} for test, report in result.failures],
        "interpretation": "Controlled os._exit process crashes; local SQLite only; no physical device or packet effect. Original signed authorization is valid, but its JSON spend and external SQLite consequence do not share a transaction.",
    })
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2], Path(sys.argv[3]))
    else:
        raise SystemExit(main())
