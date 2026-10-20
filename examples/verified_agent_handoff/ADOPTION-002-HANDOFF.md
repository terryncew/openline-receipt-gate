# HANDOFF — OPENLINE-ADOPTION-002 (2026-10-20 UTC)

**Owner-approved boundary:** New separate Draft PR on `feature/adoption-002-verified-successor-launch-20261020`, **stacked on** ADOPTION-001 Draft PR #127 head `3d1ea84c93a7778a7bdbcfca7ebc9c50ef05bb32`. Scope: only Receipt Gate feature-branch files. No edits to PR #127, main, Wallet, Lite, Half-Life, Airlock, NMF PR #24, frozen experiment protocols, original historical evidence or provider proofs. No paid APIs, real hosts/providers, downloads, production credentials/effects, merges, publication or external outreach.

**Read before editing:** original `AGENTS.md` not present at repository root (404; do not invent it); previous `examples/verified_agent_handoff/HANDOFF.md`, `README.md`, ADOPTION-001 measured results, original `olp_gate/handoff/adoption.py`, `tests/test_adoption_handoff.py`, Receiver Kit safety and native Wallet boundaries. Starting PR verified exact SHA above.

## Root cause / reproduced regression

Muse reported that a same-UID worker could overwrite the unsigned `standing.json` to resurrect an allegedly current continuation. An exact $0 demonstration in `tests/test_adoption_002_launch.py::LegacyStandingAttack` first uses real ADOPTION-001 `prepare`/`continue_to`, then (a) marks standing revoked at sequence 1, (b) resets it to active sequence 0, (c) witnesses that a legacy continuation *informational* packet still issues. The attack remains detectable/reproducible for historical honesty; there is no credible secure same-UID standing under that threat model.

**Change to old artifact:** The legacy output is now explicitly `permission_standing=UNAUTHENTICATED_LEGACY_SHARED_UID`, `authority_verified=false`, `launch_authority=false`; it still issues an information packet to keep original 10 tests and scripted quickstart usable. **The old packet is not a launch token**. New controlled launch never reads `standing.json`, `trusted-receiver.json`, the old continuation packet or the old same-UID signer.

## Supported owner-trusted launch

`olp_gate/handoff/isolated_launch.py` is Linux-only. Root controller requires a separate unprivileged Unix worker UID with no root primary group and no privilege to modify controller files, a root-owned trusted parent/control (0700), a separately root-owned external public-key pin (0600), and a root-generated owner signer (0600). The API returns/CLI prints **BLOCKED** if this OS boundary cannot be established. Supported worker is fixed synthetic Python code, **not** Claude or Codex or arbitrary shell execution.

1. `openline handoff owner-init` checks a clean exact Git HEAD/byte hashes and owner-approved JSON job, runs explicitly approved Python unittests as worker UID against a separate root-owned, read-only copied checkpoint, and **signs real observed PASS/FAIL exit codes and output hashes** plus requirements and unresolved notes. No model claim becomes an observed test.
2. Root-owned append-only-by-worker authority history is an authenticated linked chain, tied to checkpoint hash and out-of-band root-only public key. Root-owned frontier separately anchors latest sequence/hash, preventing an unprivileged worker from rolling back the ledger. `owner-revoke` appends a signed REVOKED event, fsyncs it and moves frontier under exclusive lock. Root/system-admin and all-state backup rollback remain out of threat model; this is not a hardware monotonic counter.
3. `openline handoff launch` locks authority, validates the full signed ledger, checkpoint and root, freezes tracked bytes into a root-owned read-only staging tree, verifies original HEAD/files before and after copy, checks state again under the lock, and executes actual `subprocess.run` Python worker under `setgroups([])` / distinct `setgid` / `setuid`, receiving only signed-checkpoint-derived JSON and immutable project bytes. Worker output goes only into a disposable worker-owned scratch directory; worker's attempted write of root-owned authority is denied. No arbitrary successor command, real model key or production actuation is used.
4. Controller produces signed `LAUNCHED` or `REFUSED` receipts in root-owned receipt directory; `verify_receipt` validates signature against externally pinned root. If signer/pin/key is itself corrupt, the system may hard-BLOCK without being able to produce a signed refusal; no unsigned fallback authorization. If original checkpoint races before spawn, refuse. Immutable stage guarantees model gets precisely checked bytes even if original source changes *after* spawn. No mid-execution kill/cancellation.
5. A conventional owner-managed root/UID + Ed25519 control is tested via `--baseline` and receives **the identical isolation, signing, snapshot, revocation and worker code**. This is a mechanism-level conventional parity control (not independently authored competitor). It succeeds before revocation and refuses after revocation, same as OpenLine. **No superiority** on speed, capability, integration effort, or security demonstrated.

## Actual verification

Full current focused CI: [Adoption 002 owner-isolated launch security run 39361902523](https://github.com/terryncew/openline-receipt-gate/actions/runs/39361902523) at previous code/doc head: **24/24 PASS** (10 unchanged original tests + 14 ADOPTION-002 including negative controls), $0, no provider calls. Latest committed `ADOPTION-002-RESULTS.json` contains source claims, risk limits and comparison honesty. Every subsequent doc commit must rerun the final PR head checks and record its exact SHA.

Run from repo root:
```sh
python3 -m pip install -e .
python3 -m unittest tests.test_adoption_handoff -v
sudo env PATH="$PATH" PYTHONPATH="$PWD" python3 -m unittest tests.test_adoption_002_launch -v
openline handoff owner-init --help
openline handoff owner-revoke --help
openline handoff launch --help
```
All privileged tests require a **disposable local Linux CI host** with available separate UID (nobody/65534), not a production host. Normal unprivileged machine refuses `launch`. Do not grant a worker `sudo`.

**Fair alternative:** owner-controlled POSIX identity separation, pinned signing keys, Git checks and exact same tests achieves identical observed launch/refusal in the shared implementation. Report (a) 3 owner operations `owner-init`, `launch`, `owner-revoke` plus root/key/UID/synthetic approval setup on both arms, (b) 14 scoped new test cases green, (c) no measured independent clean-install time for ADOPTION-002, (d) zero paid API dollars, (e) no reliably measured speed advantage and (f) no real-world commercial buyer evidence. Muse's reported 43.5-second install was ADOPTION-001, not this privileged setup.

## Limits and stop

**Engineering verification: PASS for the tightly supported local model. Overall ADOPTION-002 verdict: CONDITIONAL** because remaining legacy informational path is same-UID vulnerable (although not used by protected launch), the claimed end-user model remains restricted to a fixed synthetic worker, and matched conventional OS isolation performs as well. Explicitly do not call this a production revocation service, autonomous worker switch, arbitrary filesystem/network policy enforcement, mid-task kill switch, cross-machine anti-rollback protocol or unique improvement over competent conventional launcher.

Use `ADOPTION-002.md` for reproducible instructions and `ADOPTION-002-RESULTS.json` for machine-readable results. **Owner action after review only:** decide separately if stronger independent OS sandboxing, clean-user usability testing, or replacing legacy packet semantics merits a new scope. Do not automatically run more development or live workers, spend money, merge, deploy or contact third parties.
