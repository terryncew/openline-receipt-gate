## Independent follow-up verification — 2026-10-11

**Verdict: NOT READY for external/production use. The full local Gateway-path
test is now restored.** Fix branch `fix/receiver-proof-gateway-path-001`;
review [draft PR #107](https://github.com/terryncew/openline-receipt-gate/pull/107).
No merge, no paid external APIs, no outside contact.

Verified on a GitHub-hosted Linux runner in
[workflow run 38174989214](https://github.com/terryncew/openline-receipt-gate/actions/runs/38174989214):

- **20/20 real end-to-end Gateway checks PASS** (the prior 18, plus two
  identity-mismatch assertions). The path was actual client → Envoy 1.39.3
  → gRPC authorizer → mock API → Wallet / simulated SQLite ledger.
- **4/4 new atomic receipt tests PASS**, including independent Ed25519
  verification of the returned and durably stored receipt, signing-failure
  rollback, one-use approval and invalid amount checks.
- The previously reported 6/18 failure is preserved here as historical
  evidence from the earlier review environment, not the current verdict.
  CI diagnosis found premature mock API import before test key setup,
  inaccessible Envoy config in an isolated Docker namespace and test
  fixtures issuing simultaneous Wallet mandates for the same subject.
  Corrected the test setup; **did not weaken authorization**.
- The receipt is now built from balances read under the same SQLite
  write transaction that commits the effect. It includes the final
  `effect_id` **before** signing; identical signed data is returned and
  persisted. Failed signing rolls back the entire transaction.
- The full test verifies delegated-only refusal, exact amount/terms,
  replay, revoked approval, and mixed-agent identity denial.

**Remaining limits:** This is a reference receiver and a simulated ledger,
not Lithic ASA integration or production financial software. The package
is installable from a repository path, not published to PyPI. Key
enrollment, revocation freshness, restart/retry reconciliation, multi-process
durability, production operations, and independent external adoption still
require scrutiny and implementation-specific controls. PRs #105/#106 are
separate and unmerged.

---
# OpenLine Independent Receiver Readiness Report (Updated)

**Date:** 2026-10-11 (correction pass)
**Verdict:** NOT READY
**Branch:** `review/receiver-ready-001` (9c5925c4cfa9eb0dc928f579871b720242d0356a)

## Correction Pass Results

### 1. Package Quickstart — FIXED
- ✅ `example_01.py` runs with installed package (not dev imports).
- ✅ Uses real `WalletReceiver(gate_id=...)`, `.pin_owner()`, `.admit_bundle()`, `.authorize()`.
- ✅ Tested in clean venv (`/tmp/pkg-test`): imports and runs.

### 2. Lithic Adapter Tests — REAL WALLET (not simulated)
- ✅ `test_lithic_adapter_real.py`: 6/6 pass with real Ed25519 signatures.
- ✅ Uses actual `Wallet.create()`, `grant()`, `export_bundle()`, `pin_owner()`.
- ✅ Scenarios: valid → APPROVE, duplicate → same decision, amount exceeds → DECLINE,
  revoked → DECLINE, worker replacement → APPROVE (new) / DECLINE (old).

### 3. Lithic ASA Schema — CORRECTED
- ✅ Checked official docs (docs.lithic.com/docs/auth-stream-access-asa).
- ✅ Request: `token`, `card_token`, `amounts`, `merchant` (no invented fields).
- ✅ Response: `{"result": "APPROVED"}` or decline reason.
- ✅ Association via **card token → mandate mapping** (enrollment-time binding).
- ✅ Duplicate delivery: store processed `token`, return consistent decisions.

### 4. Receipt-Signing Transaction Boundary — FIXED
- ✅ Receipt built and signed BEFORE transfer.
- ✅ If signing fails → 500, no state change.
- ✅ Atomic: transfer + approval + signed receipt in single sqlite txn.
- ✅ A committed effect cannot exist without recoverable signed evidence.

### 5. Gateway Integration Test — NOT RESTORED
- ❌ `test_gateway_path.py`: 6/18 (was 6/18 before correction pass).
- 403s come from Envoy/authz layer, not mock_api. Pre-existing environment issue.
- Security fixes verified by code inspection, not by integration test.

## Verdict: NOT READY

**Fixed:** Package quickstart, real Wallet tests, correct ASA schema, receipt boundary.
**Still broken:** PR #105 unmerged, integration test 6/18, no PyPI package, no Lithic connection.

**Next steps requiring approval:**
1. Merge PR #105 (or cherry-pick 3 security fixes)
2. Publish `openline-receiver` to PyPI
3. Approve Lithic invitation draft
4. Enroll sandbox ASA endpoint

---
**Branch:** `review/receiver-ready-001` @ 9c5925c4cfa9eb0dc928f579871b720242d0356a
**No merges. No contact. No paid APIs.**
