# Show HN Fire Drill — private owner release review

**Draft/unmerged, 2026-10-20. This document authorizes no merge, deployment, public announcement, production claim or external outreach.**

## Smallest promotion scope

The Fire Drill previously lived in [Draft PR #129](https://github.com/terryncew/openline-receipt-gate/pull/129) @ \`abb523e093be9d24d6bf8b380becc568da281bf1\`, stacked on unrelated [Draft PR #127](https://github.com/terryncew/openline-receipt-gate/pull/127). A direct source import check finds the Fire Drill runner, weak fixture, verifier and playback depend only on the independently shipped Receiver Kit under \`examples/independent_receiver_kit/\` and existing \`olp_gate\` APIs already in public main \`76f72ccccce79622f40163763cf614bd1d7ff776\`.

**Promote this standalone launch Draft PR only** after explicit owner review; do not merge either #127 or #129 just to release the Fire Drill. The launch PR copies nine original Fire Drill files as their original Git blobs except the README's public quickstart, adds one narrowly scoped clean-clone CI gate and a root README entry. It does not add native Wallet adapters, the adoption agent CLI, new crypto, or any payments/production integration. The Fire Drill historical \`HANDOFF.md\` remains an **original experiment provenance record**, not a statement that release still requires #127.

From a plain GitHub clone at the proposed PR head, the free CI creates a new virtualenv, installs exactly \`pip install -e . -r examples/independent_receiver_kit/requirements.txt\`, executes the existing **32 competent JWT/OpenLine tests**, the **14 Fire Drill adversarial tests**, runs \`examples.fire_drill_001.run\`, pins a new MANIFEST SHA-256 and verifies the fresh evidence in a separate Python process. CI additionally proves \`native_wallet.py\` and the adoption agent CLI are absent. An out-of-band hash printed on the **same runner** is not independent, permanent evidence custody. The bundle is generated locally and is not a real-agent or real-payment action.

Historical clean-clone CI proof: [run 39525498324](https://github.com/terryncew/openline-receipt-gate/actions/runs/39525498324), 32/32 + 14/14 PASS, \`PASS_SCOPED_EVIDENCE\`; one fresh generated manifest SHA-256 \`7930aa5b3abd8c15bd980ab7593ed3c63a931830c8007cc55e5f5ba837bca67a\`. The manifest is **not** a downloadable evidence archive. Inspect the **latest** clean-clone CI status at PR head before any merge.

## Truth that must stay in public demo and HN text

- Local synthetic HTTP/SQLite and scripted actors. No live Claude/Codex, customer, merchant, refund, processor or settlement.
- Competent conventional EdDSA JWT and OpenLine **parity**: each refuses **4/4** protected old-worker calls after its receiver **knows** revocation. Weak shared bearer is intentionally a teaching example, not a modern competitor.
- Each of all three configurations allows **one unprotected direct SQLite write** outside the receiver. Neither secure system controls that effect path; do not claim a universal agent kill switch.
- Signed receiver decisions/effect ledger verify its recorded local observations under a pinned public test signer, not independent original backend truth, full observation or payment settlement.
- Owner-side revocation withheld from the receiving service is not covered by Fire Drill; no guarantee about in-flight work or remote propagation.
- No measured installation cost/TCO advantage, external merchant adoption or production status.

## Current live website status

A real headless Chrome session navigated to [production openlineprotocol.org](https://openlineprotocol.org) in [production browser CI run 39525661750](https://github.com/terryncew/openline-receipt-gate/actions/runs/39525661750). The two \`#proof\` triggers and one target **exist**; clicking a trigger moved scrollY from **0 to 2194**, and URL hash was \`#proof\`. The previously reported dead anchor was **not reproduced**. All five historical Fire Drill/results/verifier/source PR outbound URLs returned HTTP **200**. The current website labels the $75 guesthouse illustration educational/simulated, and the existing business calculator was present. Browser telemetry is temporary CI evidence; this did not deploy anything.

Separate [website Draft PR #9](https://github.com/terryncew/openline-hub/pull/9) prepares **link-only** changes to the new immutable launch commit and its matching source-provenance pin, so visitors who follow the website after launch land on a runnable quickstart without pulling an old stacked branch. The links must not be deployed until the appropriate Receipt Gate public commit is reachable (and the owner separately approves deployment). Do not redesign or remove the calculator.

## Required release order; currently NO-GO for posting

1. Independently review this specific Fire Drill Draft PR, CI and source/claim limits; explicit owner authorization to merge it into public Receipt Gate main.
2. Confirm the actual release/main quickstart is a normal clone and link targets match the final commit. The already verified fresh-clone PR-head test alone is **not main publication**.
3. Owner separately authorizes website production deployment of only the link fix; check it in a real browser after deployment. No need to change \`#proof\` if it remains working. Verify the website's actual source and the Fire Drill commit pin agree.
4. Owner separately authorizes any Hacker News Show submission. No HN post, public-source release or deployment occurred in this review.

**Provisional decision: ENGINEERING GO for owner code review; PUBLIC SHOW HN NO-GO until release and link/deployment gates complete.**
