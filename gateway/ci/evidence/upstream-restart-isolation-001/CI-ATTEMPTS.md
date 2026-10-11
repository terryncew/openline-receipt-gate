# Additional CI attempt record

Budget: at most three additional Docker verification CI attempts. **One used.**

| Attempt | Run | Tested commit | Result |
|---|---|---|---|
| 1 | [38124289732](https://github.com/terryncew/openline-receipt-gate/actions/runs/38124289732) | `ab60450b1601c53b634df89eb8361d76f810996d` | **SUCCESS**, all job steps completed successfully |

The branch-scoped push checked out the triggering commit on `ubuntu-latest`
with real Docker. It reproduced the untouched baseline's precise 20/22 failure,
captured direct/proxied diagnostics, and ran the complete repaired suite.
`ci-status.json` preserves Actions API run metadata and every step conclusion.
The temporary push trigger was removed afterward; there were no reruns.

Artifact/log download initially failed because its storage hosts were outside
the network allowlist. Exact host additions are saved in the environment draft.
After access became usable, both the artifact and full job logs were retrieved
and inspected: the untouched baseline reproduced exactly **20/22**; the fixed
verifier passed **25/25** with all service start times advanced, balances
**999748/252** cents unchanged across restart, and **83 valid receipts, 0 invalid**.
The artifact is preserved in `ci-38124289732/`. The repository's historical
failing evidence remains untouched, and this run uploaded its diagnostic logs
as `gateway-docker-logs` (14-day retention).
