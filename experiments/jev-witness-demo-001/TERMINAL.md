# JEV-WITNESS-DEMO-001 — Terminal Record

**Label:** JEV-WITNESS-DEMO-001 (fresh product-demo label, NOT a rescue of JEV-WITNESS-VERCEL-003)
**Terminal state:** PASS_JEV_WITNESS_DEMO_001
**Terminal SHA:** (frozen at commit below)
**Pre-contact freeze SHA:** 77a475a
**Preregistration SHA256:** 1514d52321e48b4be3660cad35ba606cd2ee81d05314ad6261349b778b869e82
**Branch:** study/jev-witness-demo-001 (unmerged, unpushed — his review gate)

## Sole intentional delta from VERCEL-003

A second risk-class receiver policy for low-consequence/reversible actions
(COMMIT >= 0.80), frozen pre-contact, COEXISTING with the VERCEL-003 policy
(0.95) — not replacing it. The 0.80 threshold is explicitly illustrative
receiver policy, NOT a claim about Jev calibration or safety (TypeSafe's own
public framing: the surrounding code chooses confidence thresholds for
autonomous action versus review; they prescribe no universal cutoff).

Protected action: trivial and reversible — write the literal text "jev-ok"
into a temporary marker file (`jev-ok.txt`) in the run's isolated
protected_workspace directory.

## Data hygiene

Synthetic, non-sensitive fixture data only. Never sent: secrets,
credentials, private repository content, personal data, unpublished research
text, production customer information, proprietary source code. This run
does NOT establish a ZDR execution path (`zeroDataRetention` deliberately
never sent; `disallowPromptTraining=true` sent and accepted on the hobby
account, live-verified 2026-09-20).

## Scientific contact

One authorized live Jev call via POST https://ai-gateway.vercel.sh/v1/evaluate
with the frozen demo request (model typesafe-ai/jev), 2026-09-20 20:55:43Z.
Credential: Secure Vault connector custom.vercel-ai-gateway via authd
surrogate exchange; the raw key never entered the process. No rerun.

- Model: typesafe-ai/jev (echoed in body, recorded as reported, never resolved)
- Generation ID: gen_01M309MZ9NJDGAP4MD2N9KV6TV
- Judgment: boolean, proceed, P(true) = 0.84
- Usage: 375 input / 21 output tokens (~$0.000016)
- Confidence: providerMetadata.typesafe.confidence present but empty {};
  boolean signal used `probability` per the documented rule

## Cases

- **V1 PASS** — signal 0.8400 >= 0.80; COMMIT; exactly one protected effect
  (jev-ok.txt with "jev-ok"); no rerun attempted.
- **V2 PASS** — owner revocation admitted (INACTIVE successor); the SAME
  signed evidence presented again -> DENY (authority:owner_standing_revoked);
  receipt still verifies (historical authenticity); effect count stayed 1.
- **V3 PASS** — same evidence presented for a different action ->
  DENY via action-binding mismatch, before any effect; substituted marker
  absent.
- **V4 PASS** — mutated state bytes -> signature verification failure
  (payload_hash_mismatch) -> DENY.
- **V5 PASS** — replay of V1's exact receipt on the protected-effect path
  after authority restoration -> DENY (evidence_replay); effect count
  stayed 1.

## Public output (verbatim, post-worthy)

```
Jev: proceed, 0.84
Receiver policy: COMMIT
Effect: executed

Owner revoked the agent.

Same Jev judgment. Same action.
Receiver: DENY
Effect: not executed
```

## Claim earned (bounded composition claim)

A receiver can choose what confidence earns for a particular consequence.
Jev supplies the judgment. OpenLine binds it to the exact action and
current authority.

## Claims NOT earned

Jev correctness, improved calibration, official TypeSafe/Vercel
partnership, Zero Data Retention, provider non-retention, production
privacy, production safety, demand, adoption.

## Release

Release bar staged: stranger with Python 3.10+ + cryptography + a Vercel AI
Gateway key can clone, set AI_GATEWAY_API_KEY, and run one documented
command (`python3 examples/jev_demo_product/demo.py`). The stranger
entrypoint was exercised to its clean credential gate (exit 2 without key);
the live request shape was served on the same gateway surface during the
frozen run. NOT published — publication is his lane. Branch parked
unmerged for his review.

## Prior records

Untouched: 001 INCONCLUSIVE_APPARATUS @ b0640cd; 002 NOT STARTED;
VERCEL-001 INCONCLUSIVE_PROVIDER_RUNTIME @ ad8270b;
VERCEL-002 INCONCLUSIVE_PROVIDER_RUNTIME @ 6d14506;
VERCEL-003 BELOW_RECEIVER_THRESHOLD @ 9ec76ba.

## Post-freeze metadata correction (no order change)

The preregistration.json as frozen at the pre-contact commit 77a475a
(sha256 1514d52321e48b4be3660cad35ba606cd2ee81d05314ad6261349b778b869e82,
authoritative for the pre-contact freeze) contained a mismatched full-SHA
string in the `baseline_sha` field: prefix `9ec76ba` was correct but the tail
was a typo. Corrected post-freeze to the actual baseline SHA
9ec76ba69c0bdf56077f0746f0ee122d43bed4e8 (VERCEL-003 terminal tip).
No frozen order element (request, policy, action, rules, claim ceiling)
changed; the correction is metadata only. Corrected preregistration.json
sha256: 2db31044c264fda628355e2e30577fe161301a47f2f887e0957a46007f0435bf.
