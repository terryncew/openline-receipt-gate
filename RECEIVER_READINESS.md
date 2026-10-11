# OpenLine Independent Receiver Readiness Report

**Date:** 2026-10-11
**Verdict:** NOT READY

## What Actually Works

### PR #105 (Poppy-proof) — Fixed during review
- ✅ **Atomic approval consumption:** `transfer_with_approval()` does ledger
  transfer + approval marking in a single sqlite transaction. No double-spend
  window on crash. (Fixed: was two separate commits.)
- ✅ **Fail-closed signatures:** If receipt signing fails, the request fails
  with 500. No unsigned receipts returned. (Fixed: was 200 with `signature_error`.)
- ✅ **Identity separation:** Wallet mandate's `subject_id` must match Gateway's
  `agent_id`. Rejects 403 IDENTITY_MISMATCH if mixed. (Fixed: was unchecked.)
- ✅ One-use enforcement, amount binding, revocation via bundle freshness.

### PR #106 (Latency) — CI green
- ✅ All CI checks pass (contract 3.10-3.13, cpg001, external-replay, verify).
- ✅ Original concurrency failures (c8, c32) preserved as documented negative
  results in `gateway/latency001/REPORT.md`. Not erased.
- ✅ Optimized path is faster AND maintains atomicity (serializes sqlite txns).

### Receiver Kit — External install tested
- ✅ `01-minimal-receiver.py` runs in clean venv with only:
  `openline_wallet/`, `wallet_bridge.py`, `cryptography` package.
- ✅ `03-revocation.py` works: revoke → old presentations STOPPED.
- ✅ No hidden dev dependencies.

## What Remains Broken

### 1. PR #105 not merged
The atomicity, fail-closed, and identity fixes are on the branch
`experiment/openline-poppy-proof-001` but PR #105 is still open.
An independent receiver cannot use these fixes until merged (or they
cherry-pick).

### 2. No standalone receiver package
The `openline_wallet/` contracts are vendored inside the
openline-receipt-gate repo. There is no PyPI package, no `pip install
openline-receiver`. An external developer must:
- Clone the entire openline-receipt-gate repo (or copy files manually)
- Figure out which files are the "receiver" vs the "gateway" vs "demo"
- The VENDOR-README says "do not modify" but doesn't say "how to install"

### 3. Owner key distribution is manual
The trust model says "pin the owner's root key out-of-band" but provides
no mechanism. For Lithic ASA, this means: how does Lithic get the card
holder's root key? Email? API? There's no enrollment flow.

### 4. No production hardening
- SQLite is fine for demo, not for a payment processor.
- The 60s challenge TTL is hardcoded in places.
- No rate limiting, no audit log shipping, no monitoring.

## What an Independent Developer Would Need to Do

**Today (with the kit):**
1. Clone `terryncew/openline-receipt-gate` (entire repo, ~50MB)
2. Copy `gateway/openline_wallet/` and `gateway/wallet_bridge.py` to their project
3. `pip install cryptography`
4. Read `gateway/receiver-kit/examples/01-minimal-receiver.py` (60 lines)
5. Adapt the `WalletReceiver` class to their API framework
6. Figure out how to get the owner's root key (out-of-band, undefined)
7. Implement bundle refresh (manual in example, needs automation)
8. Write their own receipt verification (example shows signing, not verifying)

**Missing:** A `pip installable` package, a 5-minute quickstart that doesn't
require reading 60 lines of example code, and an enrollment flow for key
distribution.

## Recommendation

**NOT READY** for an independent receiver integration.

The core cryptography and protocol are sound. The atomicity and identity
fixes I made today close real gaps. But the packaging is not there:
- PR #105 must be merged (or the fixes extracted)
- Need a minimal `openline-receiver` PyPI package (just `openline_wallet/` + `wallet_bridge.py`)
- Need a documented key enrollment flow (even if it's "email us your root key")

The smallest credible step: publish the receiver kit as a standalone repo
or PyPI package, with a README that starts "pip install openline-receiver"
and ends with "you just enforced an owner-signed mandate."

---

**Prepared by:** Muse
**Evidence:** PR #105 branch (unmerged), PR #106 CI (green), /tmp/external-test (clean install)
**Next:** Draft invitation for Lithic ASA (below). Awaiting approval to contact.
