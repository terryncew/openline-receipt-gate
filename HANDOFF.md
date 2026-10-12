# OpenLine Lithic handoff — owner review only

**OFFLINE ACCEPTANCE: PASS. EXTERNAL EXECUTION: NO-GO, including unarmed calibration.** Read the [latest evidence closure](docs/lithic-review/external-gates/EVIDENCE_CLOSURE.md) and [containment review](docs/lithic-review/external-gates/CONTAINMENT_REVIEW.md) before earlier plans. Calibration is owner-approved **in principle, not for execution**. The latest authorization permits this documentation/evidence commit and push on the existing branch, with no experiment.

## Objective, repository, HEAD and frozen baselines

Objective: determine whether a bounded Lithic ASA sandbox experiment can demonstrate an independently operated receiver enforcing owner-issued Wallet authority, admitted revocation and worker succession, with independently verifiable receipts. Ordinary card controls may solve spending safety more simply. A single-provider result cannot establish provider portability or a unique OpenLine advantage.

- Repository: https://github.com/terryncew/openline-receipt-gate
- Working branch: `codex/openline-lithic-preflight-001`; [draft PR108](https://github.com/terryncew/openline-receipt-gate/pull/108), targeting `fix/receiver-proof-gateway-path-001`. The handoff push advances only this existing head; no PR body/state change or merge.
- **HEAD reviewed before handoff:** `8a537d4ff598541bb21cc564b3220ec97ef09fb3`, original documentation delivery. Final handoff HEAD is the commit containing this file on this branch, visible in GitHub commit metadata and the final delivery receipt. Obtain it with `git rev-parse HEAD` or the branch's GitHub commit SHA. A documentation HEAD is not a new tested runtime SHA.
- **Tested implementation:** `abf6bc72f4375bd43d2c274812e5dadd68f03e41`. Its24 runtime/fixture/requirements/test files matched delivery byte for byte. This handoff changes no application/test/dependency/workflow or old evidence file.
- **PR107 verified baseline:** `8a2ddf2af62374b70908421da6066afb69d5803e`; [PR107](https://github.com/terryncew/openline-receipt-gate/pull/107) remains open/draft at that head. Seven protected Gateway identity/receipt source/config/test files are unchanged. Do not merge it.
- Adapter source reviewed/ported during preflight: `fix/lithic-adapter-secure-001` at`7a9d51400900a506a0c2db02382d0afcf500ead0`. This older branch is not the tested starting baseline.
- Original frozen Gateway experiment: `f86c23d59dc2a29240c79b8b3628ab98745df12d` (20/22 report). [PR103](https://github.com/terryncew/openline-receipt-gate/pull/103) merged restart repair into `experiment/gateway-subscription-001` as`9461188f44a15766d35dcf034d386c682db403f7`; [draft PR102](https://github.com/terryncew/openline-receipt-gate/pull/102) now points there. Do not overwrite Muse's branch, alter historical/frozen baselines, main or other branches.

## Completed work and exact verdicts

| Work | Evidence |
| --- | --- |
| Preflight implementation | Verified owner-root revocation admission, actual Wallet verification, worker-signed intent, mandatory raw-body ASA HMAC, token/content decisions, atomic receipt persistence/crash/corruption guards and authenticated receipt retrieval. [Contract](gateway/receiver-package/LITHIC_CONTRACT.md), [report](gateway/receiver-package/LITHIC_PREFLIGHT.md). |
| Passing implementation Linux CI | [38182746885](https://github.com/terryncew/openline-receipt-gate/actions/runs/38182746885), head abf6bc72: **72 receiver tests + 7 Gateway atomic/crash tests + 25 real Envoy/Wallet checks =104/104 PASS**. |
| Independent clean acceptance | Installed exact delivery package; imported adapter from site-packages and verified byte hash. **72/72 PASS in17.772s, zero skips; 7/7 PASS in0.270s; 25/25 PASS.** [Fresh log](docs/lithic-review/acceptance/clean-preflight-tests.log), [atomic log](docs/lithic-review/acceptance/gateway-crash-tests.log), [integration log](docs/lithic-review/acceptance/gateway-integration-tests.log), [runtime provenance](docs/lithic-review/acceptance/installed-runtime.json). |
| Evidence/signatures | All39 original manifest hashes verified; four public measurement files retrieved from CI matched preserved bytes. Independent cryptography-only verifier checked19 Ed25519 signatures, heads1→2→3 and APPROVED→CARD_PAUSED→APPROVED. [Provenance](docs/lithic-review/acceptance/provenance.json), [CI comparison](docs/lithic-review/acceptance/ci-evidence-comparison.json), [chain result](docs/lithic-review/acceptance/authority/public-chain-result.json). |
| Skeptical probes | Six authority probes passed; state review ran31 overlapping regressions, all passed. Old-state restoration reproduced an excluded trusted-host boundary. Do not inflate104 with overlapping counts. [Authority review](docs/lithic-review/acceptance/authority/AUTHORITY-AUDIT.md), [state review](docs/lithic-review/acceptance/state/state-audit.md). |
| External evidence closure | Provider gates and all three containment configurations remain UNRESOLVED in material parts. [Latest matrix](docs/lithic-review/external-gates/EVIDENCE_CLOSURE.md); support questions drafted but unsent. No external provider test. |

Offline104 is accepted historical evidence, **not rerun for research/closure/handoff**, and not a fresh complete Docker Compose run. Earlier complete localhost timings: three-step sequence4.83–7.21ms; 80 duplicate requests at concurrency8 maximum33.87ms; eight unavailable-writer503 responses maximum1.009s. The requested local six-second target is not a proven Lithic deadline or deployed guarantee.

## Failures, uncertainty and exact blockers

- **Matching:** current SDK exposes15 inputs, published OpenAPI13. Complete generated acquiring-institution/POS/AVS/risk/authentication context is not controlled by those inputs; no applicable predictable callback template is supplied. Lab merchant ID length22 exceeds simulator limit15. Use explicit100/USD; SDK/OpenAPI currency descriptions differ, without observed API failure.
- **Provider failure:** documented5XX→one immediate retry and unknown string→CUSTOM_ASA_RESULT decline. Final timeout/late/exhausted503/malformed/invalid-shape behavior and deadline/time origin remain unestablished. Deprecated approximate`ttl`, SDK timeout and demo Lambda timer are not that deadline. Local503 is not issuer decline. Docs website previously returned proxy403; unseen contents are not claimed.
- **Containment:** no selected program/card/endpoint inventory or applicable isolation statement, actual caller/ingress/abort configuration, costs/count exists. **UNRESOLVED**, not demonstrated provider fail-open or unsafe deployment. C1 requires separate fresh state/new receiver identity/no historical approvals; C2 requires guarded sandbox destination and disabled overrides/redirects/retries; C3 requires serial allowance/latch, reconciliation before another POST and named operator/safe-decline abort plan.
- **FAILED sufficiency claims:** empty pending state or `initialize=True` alone does not ensure unarmed state; existing valid DBs reopen and historical APPROVED retries return. SDK defaults are not strict sandbox containment: production default, explicit URL precedence and redirects. These are source counterexamples, not PR108 regressions or live incidents.
- **Preserved historical failures:** initial96-check green CI at`52fe9e74383d0f59da7966449c2c04ee0413e0a2` missed cached approvals after physical state corruption; final abf6bc72 fixes it with8 additional HTTP cases. An intermediate queued writer failure took8.019s; cached-column/pending-proof defects were fixed. Old`quickstart.py` already fails at PR107 on a fictitious principal. [Failure evidence](gateway/receiver-package/evidence/preflight-001/failures), [baseline quickstart log](gateway/receiver-package/evidence/preflight-001/local-baseline/quickstart.log). Preserve them.

## Conversation findings that must survive

1. Owner grants reusable`lithic:authorize`; receiver enforces100USD cents **per request**, worker signs terms. Neither owner-signed exact purchase consent nor total$1 cap. Two different-merchant$1 purchases passed under one unchanged owner grant.
2. First matching authenticated ASA within at most60seconds consumes intent. Identical purchases remain indistinguishable; a matching callback created/HMAC-signed120seconds earlier consumed a later intent within300-second signature freshness. Token exists **in ASA before decision**, not as an advance selectable token.
3. Revocation starts at successful receiver admission/commit, not signing or undelivered update. Historical approval retries remain legitimate acknowledgments after revoke. A decline normally has NO_PENDING_AUTHORIZATION/no authority proof; prove causality through valid unconsumed intent, admission ordering and unchanged issuer controls/allowance.
4. Restoring coherent older DB state under the same receiver pin can revive pending authority. The pin authenticates identity, not storage freshness. No old-state restore/protected trusted host is the documented boundary; no hostile-admin, power-loss or multi-host guarantee.
5. Public lab signatures/pins do not prove real owner/card enrollment. SDK HMAC compatibility is not provider-origin ASA interoperability; receipts prove decisions, not settlement/goods.
6. Latest containment/closure addenda supersede earlier five-probe budgets and arbitrary30-second silence suggestions. Five cases are a catalogue; written answers first, only discriminating probes. Historical RESULTS JSON must not override these addenda.
7. Calibration tests provider mechanics; later independent authority/worker-succession tests are separately approved. One Lithic result cannot prove provider replacement. Native controls or an equivalent stateful policy gate remain fair alternatives.

## Reproduce or continue without this workspace

GitHub-only ChatGPT can read these linked files, immutable official-source links and committed logs directly. Read latest closure → containment → [acceptance audit](docs/lithic-review/acceptance/AUDIT.md)/[owner packet](docs/lithic-review/acceptance/OWNER_APPROVAL_PACKET.md) → [source research](docs/lithic-review/external-gates/REPORT.md)/[captured contracts](docs/lithic-review/external-gates/extracted-contracts.json).

Portable exact104-suite install/copy/run/Envoy-extraction commands already reside in [LITHIC_PREFLIGHT.md, Reproduce](gateway/receiver-package/LITHIC_PREFLIGHT.md#reproduce) and [.github/workflows/openline-lithic-preflight-001.yml](.github/workflows/openline-lithic-preflight-001.yml). **Do not repeat them unless new evidence specifically justifies revalidation.** Python3.12, cryptography50.0.1, standardwebhooks1.1.0, jsonschema4.26.0, grpcio1.84.0, protobuf7.36.2 and Lithic0.132.0 at`a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f` were used. Requirements and package paths are repository-relative.

From a clone on this branch, inspection and public-proof commands (no Lithic API key required):

```bash
git rev-parse HEAD
git diff --exit-code 8a537d4ff598541bb21cc564b3220ec97ef09fb3 -- gateway/receiver-package gateway/poppy gateway/authz_server.py gateway/mock_api.py gateway/wallet_bridge.py gateway/envoy .github/workflows
# Use the virtualenv installed by the preflight's Reproduce commands:
/tmp/lithic-preflight-venv/bin/python gateway/receiver-package/verify_pilot_receipts.py \
  --evidence gateway/receiver-package/evidence/preflight-001/ci-final/measurements/asa-sequence-public-evidence.json \
  --pinned-public-key gateway/receiver-package/evidence/preflight-001/ci-final/measurements/receiver-pinned.pub
/tmp/lithic-preflight-venv/bin/python docs/lithic-review/acceptance/authority/verify_public_chain.py
python3 - <<'PY'
from pathlib import Path
import hashlib, json
for root, manifest in [(Path('gateway/receiver-package/evidence/preflight-001'), 'SHA256SUMS.json'),
                       (Path('.'), 'docs/lithic-review/PUBLICATION_SHA256SUMS.json')]:
    hashes = json.loads((root / manifest).read_text())
    bad = [name for name, digest in hashes.items()
           if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not bad, bad
    print(manifest, len(hashes), 'PASS')
PY
```

Synthetic probe sources: `docs/lithic-review/acceptance/authority/probe_authority_limits.py` and `state/extra-state-probes.py`; set `PYTHONPATH` to `gateway/receiver-package` for fixture imports. `OPENLINE_AUDIT_OUTPUT` selects state output (default`/tmp/openline-lithic-state-probes`). Two evidence/output paths and Markdown links were adapted for transfer; proof logic unchanged and not rerun. No test-only secret is a real pilot credential.

[TRANSFER_ORIGINS.json](docs/lithic-review/TRANSFER_ORIGINS.json) records original/published hashes. [Publication checksums](docs/lithic-review/PUBLICATION_SHA256SUMS.json) verify transferred bytes; `WORKSPACE_SHA256SUMS_HISTORICAL.json` files describe original workspaces, not adapted paths. Old stdout/prose `/workspace` paths are historical. No private key, DB/WAL/SHM, credential/environment file, cache or virtualenv is published.

## Smallest next action, falsifier and restrictions

**Next action: review nonsecret applicable written evidence and C1/C2/C3 configurations.** Three provider questions (isolation/scope; complete100USD callback profile; failure/deadline/abort matrix) are drafted in the closure; none sent. Selected resource provenance/configuration is an owner-side requirement. Do not ask for credentials or run a probe to compensate for missing evidence.

Readiness falsifier: an answer/config permits real-network/fund routing, fallback approval without authority, uncontrolled destination/redirect/retry, old approvals, or continued POSTs after ambiguity—or supplies no applicable evidence. Keep NO-GO. Written answers eliminate probes. Only after containment review, separately approved setup/runtime validation and **new explicit execution approval** consider a normal unarmed decline and only unresolved distinctions. Unexpected provider approval/partial approval or matching drift falsifies that run; latch caller off and reconcile only through separately approved reads. Teardown does not cancel an approval; do not remove endpoints blindly.

Restrictions persist: no credentials/private-key publication/secret-file inspection, provider API or secret-retrieval/rotation/enrollment, outside contact/invitations, card creation/use, synthetic external transaction, real funds/purchase, financial authorization/clearing/settlement, paid API/new service, public deployment/production change or merge. Even GET ASA-secret retrieval can mutate state. No changes to protected/frozen branches, main, Muse's branch, PR107, old evidence, runtime/tests/assertions, security/freshness/durability or CI triggers. GitHub documentation/evidence commit/push on **this working branch only** is explicitly authorized; it implies no outside messaging or experiment permission. Stop for owner approval afterward.

## Related earlier work — separate evidence

- **Restart repair:** [PR103](https://github.com/terryncew/openline-receipt-gate/pull/103) merged; branch `codex/upstream-restart-isolation-001` at`b921722b87e3398e996c0c3dda27b3e076b10890`. [Docker CI38124289732](https://github.com/terryncew/openline-receipt-gate/actions/runs/38124289732):25/25, post-restart balances999748/252 cents,83 valid receipts/0 invalid. Root cause was revoked verifier client plus profile-gated restart no-op, not established Envoy outage. [Immutable report](https://github.com/terryncew/openline-receipt-gate/blob/b921722b87e3398e996c0c3dda27b3e076b10890/gateway/ci/evidence/upstream-restart-isolation-001/README.md).
- **Latency:** [draft PR106](https://github.com/terryncew/openline-receipt-gate/pull/106), branch `codex/gateway-latency-001`, remote observed head`d4267eb725bf0a0a36394fe37e5c95c01122b82d` (local older head`413e99abb7cc84745c890605a98663bd46654572`). [Pinned report](https://github.com/terryncew/openline-receipt-gate/blob/d4267eb725bf0a0a36394fe37e5c95c01122b82d/gateway/latency001/REPORT.md): REVIEW/NO MERGE; [CI38161773565](https://github.com/terryncew/openline-receipt-gate/actions/runs/38161773565) required optimized/correctness cases passed, **overall prior workflow FAIL** with original concurrent diagnostics failed. Revised reporting needs its own validation, not authorized here. Historical218ms-vs76ms was not reproduced; attribution INCONCLUSIVE. Do not switch branches/resume experiments or claim a final complete benchmark PASS.

All consequential session-only findings and public evidence are reachable here. The next executor needs GitHub access only to continue evidence review.
