# HANDOFF: HOME-GUARD-001 Muse prototype -> Codex hardening review

Branch: `study/home-guard-001` (cut from main @ `31070c8`, nothing merged).
Issue: terryncew/openline-receipt-gate#110. Scope: first local proof only.
No feature expansion — harden what is here against the frozen criteria.

## What was built

`experiments/home-guard-001/`: offline prototype of two receiver-owned
boundaries (AI action authority; device-to-device reachability), 8 frozen
security tests (all PASS, deterministic), executable demo, THREAT_MODEL.md,
REPRODUCE.md, EVIDENCE.md, FREEZE.json. Receipt signing reuses
`olp_gate.crypto` / `olp_gate.receipts` from this repo.

## Hardening targets (in priority order)

1. **Replay/nonce and revocation state is in-memory.** `seen_nonces`,
   `executed_nonces`, and the revocation list die on restart. A restarted
   receiver would re-execute a spent token. Decide: durable store with
   crash semantics (cf. WALLET-STANDING-004 durability rule), or prove the
   prototype's single-run scope makes this acceptable and say so.
2. **Clock.** `FixedClock` is a test fixture; a real receiver needs a stated
   clock model (skew bounds, expiry enforcement). `expires_at` string
   comparison is placeholder-grade.
3. **Binding surface.** `devices.apply()` checks device/action/params/nonce
   binding — audit for missing fields (e.g. `mandate_id` is in the receipt
   but not cross-checked at apply time; `proposal_sha256` likewise).
4. **net_policy re-sign wart.** `attempt()` signs, then re-signs when
   `route_created=true`. Restructure so the body is final before the single
   sign.
5. **Identity registry assumption.** Spoof-resistance rests on the registry,
   which the simulator populates by fiat. Name what a real binding would
   require; do not silently keep the fiat.
6. **Forwarding gap.** Relay paths return OUT_OF_SCOPE. Either model
   forwarding explicitly (with deny rules for it) or keep OUT_OF_SCOPE and
   confirm the non-claim stays intact in every doc.
7. **Error-path audit.** `_log_reject` records rejections; check no failure
   mode returns `applied=True` implicitly (all returns are explicit tuples —
   verify this holds after any refactor).

## Unresolved assumptions (do not resolve by redefining them)

- Single-process simulation: receiver, devices, and network share memory.
  Real separation (processes, hosts, firmware) is untested.
- Test keys are fixtures; key management, rotation, and compromise recovery
  are out of scope.
- `ip netns` packet-isolation test infeasible here (`setns: Operation not
  permitted`); a privileged environment could add it as a separate,
  labeled proof.
- Revocation-to-deny latency (0.26 ms) is an in-process measurement, not a
  propagation claim.

## Falsifiers

- Any frozen test failing after hardening (tests must not be weakened).
- A bypass path producing an effect or a route without a corresponding
  FAIL/OUT_OF_SCOPE record.
- A second demo run producing a different receipts hash (determinism break).
- Any doc sentence equating simulator DENY with real-world reachability.

## Frozen criteria

`FREEZE.json` pins the test file SHA and the 8 test names. Harden the
implementation; the criteria move only on the owner's explicit order.
