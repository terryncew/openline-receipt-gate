# HOME-GUARD-004 — Results summary

**Question:** Can a fresh operator reproduce Home Guard's receiver-enforced
revocation in a disposable virtual network, independently verify the evidence,
and measure the additional work required to protect more devices?

**Answer: yes for the first two, partially for the third.**

## What worked

- **Reproduction:** the full PR #113 mechanism re-ran on a disposable
  GitHub Actions runner (ubuntu-latest) from one documented command
  (`run_measured.sh`). Verdict: `PASS_SIGNED_POLICY_TO_KERNEL_REVOCATION_IN_VIRTUAL_NETWORK`.
- **Security observations (CI run 39152946810):**
  - 9 application-payload packets reached NVR before revoke; **0 after**.
  - Established TV socket attempted 19 post-revocation sends; **0 ACKs**.
  - New TV connection + alternate port: **timed out**. Forged source: seen at
    TV ingress, **not** at HVAC egress.
  - Thermostat → HVAC: **2/2** before and after.
  - Kernel counters: 8 revoked-flow DROPs, 3 spoof/alt-port DROPs, 6 legitimate ACCEPTs.
  - **2** owner policies applied (v1→v2), **5** hostile updates rejected
    (forged signer, rollback ×2, expired, tampered); **7/7** receipts verify.
  - `conntrack -D`: exit 0, evicted the ESTABLISHED TV/NVR flow (5.6 ms).
- **Independent verification:** `verify_evidence.py` re-run locally on the
  downloaded artifact → PASS (all PCAP digests, 7 receipt signatures,
  kernel-rule binding, sqlite ledger).
- **Hostile evidence tamper:** flipped one byte in a receipt signature →
  verifier rejected (`signature_invalid`). Tampering is detectable.
- **Costs measured** (see COST_REPORT.md): cold setup 1.36 s scripted;
  revocation 28.5 ms submit→receipt (kernel enforcing), 1.41 s to confirmed
  observation; verification 156 ms; per-device marginal ~0.5 s machine time.

## What failed / is limited

- **Local VM cannot run it.** No conntrack kernel module, no `conntrack`/`tcpdump`
  tools, no host `CAP_SYS_ADMIN`. (Same blockers as PR #122.) All kernel
  evidence is from disposable CI runners.
- **5th device not supported.** The policy schema fixes exactly two device
  pairs; a third pair requires schema redesign. Marginal cost is flat *within*
  the schema, but the schema does not scale.
- **Single receiver, single run.** No multi-receiver propagation, no soak test.
- **Trusted components unchanged from PR #113:** test-only keys, trusted
  updater + root firewall, SQLite ledger not attacker-resistant.

## Commercial position

The measured numbers strengthen the honesty story, not a uniqueness story:
revocation is fast (~28 ms to kernel enforcement with signed receipt), cheap
to verify (156 ms), and tamper-evident. But per the PR #12 correction, Ratify
or another system could achieve equivalent enforcement — the advantage, if
any, must come from operational ease and cost, which are now measured for
OpenLine's side only. A fair cross-system comparison is still missing.

**Verdict: READY_FOR_OWNER_REVIEW** (with the limitations above intact).
