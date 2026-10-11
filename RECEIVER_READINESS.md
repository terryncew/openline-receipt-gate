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
