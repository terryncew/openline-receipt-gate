# GATEWAY-SUBSCRIPTION-001 Step 1 — EVIDENCE (Docker Compose path)

**Verdict: NOT VERIFIED.** Four full CI attempts on GitHub Actions
(`ubuntu-latest`, real Docker). Best result: **14/21 checks passed**
(attempt 4). The remaining failure has a diagnosed root cause and a
fix committed, but the fix has **not** been executed in CI (attempt
budget exhausted — see "Attempt record"). Nothing below is claimed as
verified until a green end-to-end run exists.

Branch: `experiment/gateway-subscription-001`
Repo: `github.com/terryncew/openline-receipt-gate` (local clone:
`~/workspace/repos/openline-receipt-gate`)

---

## 1. What was tested

`.github/workflows/gateway-subscription-001-docker.yml`
(workflow_dispatch-only in its final state) brings up
`docker compose --profile openline up --build -d` (`AUTH_MODE=openline`)
in `gateway/compose`, waits for Envoy on `127.0.0.1:8080`, then runs
`gateway/ci/docker_verify.py`, which (using the repo's
`agent_client.AgentClient` unmodified):

- a. signed transfer → 200; tampered signature → 403; replay → 403
- b. GET `/balance/treasury` + `/balance/vendor` (via Envoy, signed
  `inspect` headers) before/after a 100-cent transfer; asserts treasury
  −100 and vendor +100 exactly
- c. `gateway_admin.py verify-receipts` exits 0 with 0 invalid
- d. `docker compose restart mockapi` → balances survive
- e. `revoke-agent` → next fresh request 403
- f. `docker compose restart` (full stack) → balances + receipts survive

Artifacts (container logs + verifier output) uploaded per run
(`gateway-docker-logs`).

---

## 2. Attempt record (all 4 budgeted attempts used)

| # | Run ID | Head SHA | Result |
|---|--------|----------|--------|
| 1 | 38121276650 | `cd9aea1` | **FAIL** — image build: `COPY olp_gate` / `COPY gateway` → "`/olp_gate`: not found", "`/gateway`: not found" |
| 2 | 38121356866 | `89c1672` | **FAIL** — Envoy exits critical: `malformed IP address: authz` |
| 3 | 38121652597 | `3cca39c` | **CANCELLED** by operator before doing work (doomed: STATIC clusters not yet fixed on this branch; superseded by attempt 3-retry) |
| 3r | 38121686646 | `98165d3` | **FAIL** — `authz-1` Exited(0) right after init (no server lines); Envoy healthy in-container but `127.0.0.1:8080` refused, `docker ps` PORTS column empty |
| 4 | 38122041694 | `bb7b945` | **FAIL** — **14/21 checks passed** (see §3) |

A fifth run is **not** taken on this agent's authority (budget cap).

### Dispatch mechanism (deviation from the task order, recorded)

`gh workflow run gateway-subscription-001-docker.yml --ref
experiment/gateway-subscription-001` and the direct
`POST .../actions/workflows/.../dispatches` API both returned **HTTP
404** ("not found on the default branch"). Verified cause: GitHub only
discovers `workflow_dispatch` workflows from the **default branch**;
a workflow file existing solely on a feature branch is not
dispatchable, and this task forbids touching `main`. Workaround used:
a TEMPORARY path-scoped `push` trigger (branches:
`experiment/gateway-subscription-001`, paths limited to the workflow
file, `gateway/ci/**`, `gateway/compose/**`, `gateway/gateway_admin.py`)
so the verification could run at all. The trigger was **removed** in
the final state — the committed workflow is `workflow_dispatch`-only
per the task spec. Re-running CI later requires re-adding the
temporary trigger or landing a stub of the file on `main`.

---

## 3. Attempt 4 detail (run 38122041694, `bb7b945`) — 14/21 PASS

PASS (measured):
- provision-agent exits 0; key JSON printed
- a2 tampered signature → **403** (`signature_invalid`)
- a3 replay of same headers → **403** (`replay_detected`)
- c `verify-receipts`: exit 0, **0 invalid**
- d0 mockapi restart exits 0
- e0 revoke-agent reports `revoked`; e1 fresh request → **403** (`agent_revoked`)
- f0 stack restart exits 0; f1 Envoy `/health` after restart; f2 authz
  chain live after restart (structured `missing_action_claim` deny);
  f4 receipts survive (0 invalid, none lost)
- (d2/f3 "balances survive" passed **vacuously** — see hardening note)

FAIL (all one root cause):
- stack-ready, a1, b0, b1, b2, b3, d1 — Envoy returned **503**
  `upstream connect error or disconnect/reset before headers. reset
  reason: remote connection failure` for every request needing the
  mock API upstream. ext_authz itself worked (the 403s above came from
  the live authz service).

**Root cause:** `mock_api.py` bound `127.0.0.1:9000` — the container's
own loopback. Envoy reaches it via the container's bridge-network IP,
so every upstream connection was refused. (Invisible in `./up.sh`
mode, where all processes share the host loopback — another instance
of "never run in Docker" rot.)

**Fix committed (NOT CI-verified):** `MOCK_API_HOST` env var
(default `127.0.0.1`, preserving `./up.sh` behavior) +
`MOCK_API_HOST: "0.0.0.0"` in the compose file for `mockapi`.
Locally verified the bind: `0.0.0.0:19001` LISTENs and serves
`/health`; default path unchanged.

**Verifier hardening (committed):** d2/f3 balance-survival checks now
require a valid non-negative baseline (`t1 >= 0`) so they cannot pass
vacuously again.

**Measured latencies:** attempt-4 transfer samples (Envoy-level,
requests that 503'd): 4.6 ms, 3.4 ms. Local full-path measurements
(real Envoy + services on the build VM, §5): signed transfer 200 in
**154.0 ms** (cold, includes gRPC conn setup) then **4.7 ms** (warm);
balance GET via Envoy **7.3 ms**.

---

## 4. Failures found and fixes applied (all committed on the branch)

1. **Empty `gateway-config` volume** (the suspected blocker —
   confirmed): `authz_server.py`/`mock_api.py` crashed with
   `FileNotFoundError` on missing `receiver.key`/`policy.json`
   (reproduced locally). Fix: `gateway/compose/entrypoint-gateway.sh`
   runs `gateway_admin.py init` on first boot, atomic via a
   mkdir-lock (both services boot concurrently); wired as
   `entrypoint:` on `authz` and `mockapi`. CI-verified working
   (attempt 3/4 logs show init + peer-wait).
2. **Envoy 127.0.0.1 upstream endpoints**: inside the Envoy container,
   loopback is itself. Fix: `gateway/compose/envoy-openline-compose.yaml`
   with service-name endpoints (`authz:50051`, `mockapi:9000`);
   host-mode `envoy-openline.yaml` untouched (`./up.sh` unaffected).
3. **STATIC clusters reject hostnames**: Envoy exited critical
   (`malformed IP address: authz`). Fix: `STRICT_DNS` on both clusters
   (same fix the sibling receiver-001 lane made independently).
4. **Wrong Docker build context**: `context: ..` (gateway/) but the
   Dockerfile copies repo-root-relative `olp_gate/` + `gateway/`.
   Fix: `context: ../..`, `dockerfile: gateway/compose/Dockerfile.gateway`
   on all three build services.
5. **`internal: true` network silently drops port publishing**:
   Envoy healthy in-container, but `docker ps` PORTS empty and
   `127.0.0.1:8080` refused on the host. Fix: removed `internal: true`
   (only Envoy publishes a host port; authz/mock API remain reachable
   only inside the bridge network).
6. **authz silent exit(0)**: relied on image CMD propagating through
   the entrypoint override; container exited 0 with no server lines.
   Fix: explicit `command: ["python3", "/app/gateway/authz_server.py",
   "50051"]` on the authz service; entrypoint now echoes the exec'd
   command and exits 1 (loud) if CMD is ever empty. CI-verified:
   attempt-4 log shows `[entrypoint] exec: python3
   /app/gateway/authz_server.py 50051` → `[authz] listening on :50051`.
7. **`--max-cents 5000` (space form) silently ignored**:
   `provision-agent` used the default 10000 (verified against the DB).
   Fix: `gateway_admin.py` accepts both `--max-cents 5000` and
   `--max-cents=5000`. Locally verified both forms.
8. **mock_api bind address** (§3): fix committed, **not CI-verified**.

---

## 5. Local validation (build VM, real Envoy binary, no Docker)

Full stack via `./up.sh`-equivalent with the repo's Envoy binary:
- signed transfer → **200** (`{"ok": true, ...}`, 154.0 ms cold / 4.7 ms warm)
- tampered signature → **403** (`signature_invalid`)
- replay → **403** (`replay_detected`)
- balance GETs through Envoy (signed `inspect` headers) → **200**
- 100-cent transfer: treasury 999945 → 999845 (**Δ −100**), vendor 55 → 155 (**Δ +100**)
- `verify-receipts`: **9 valid, 0 invalid**, exit 0
- `revoke-agent` → fresh request **403** (`agent_revoked`)
- entrypoint init/skip-idempotency and both `--max-cents` forms verified
- existing unit tests: `test_gateway.py` 5/5 pass (the 9 errors in
  `test_standing_races.py` pre-date this work — verified by stashing)

---

## 6. What remains unverified

- **The Docker Compose path end-to-end** (the point of this step):
  no green CI run exists. One more run is needed after the mock_api
  bind fix.
- The `MOCK_API_HOST` fix itself (committed, never run in CI).
- The OPA profiles (`opa-a`/`opa-b`) in Compose: `envoy-opa.yaml`
  still uses 127.0.0.1 endpoints; never attempted.
- `make quickstart` / `make up` with the fixed compose file (no
  Docker on the build VM; the Makefile path inherits the same fixes).
- `workflow_dispatch` dispatchability: still 404s until the file
  exists on `main` (forbidden by this task).

## 7. Coordination notes (shared branch/clone)

- A sibling agent works the same branch (`GATEWAY-SUBSCRIPTION-001`
  steps 2/4) and later branched `experiment/openline-receiver-001`
  off it. It twice switched the shared clone's checked-out branch
  mid-task (recovered: cherry-picked my commits back, reset its branch
  to origin, never pushed to it).
- It renamed my workflow file to `gateway-docker-verify.yml`
  (I restored `gateway-subscription-001-docker.yml`; both coexist)
  and independently fixed STATIC→STRICT_DNS (I applied the same fix
  on this branch).
- Its committed `authz_server.py`/`mock_api.py` changes (standing
  endpoint) are env-gated (`GATEWAY_STANDING_PORT`,
  `GATEWAY_STANDING_CHECK`), default off — the verified default path
  is unaffected. My commits touch only my own files.
- `gateway/docs/FAILURES.md` was NOT edited (per task; the coordinator merges).

## 8. Exact commands run

```bash
# diagnose + fix (branch experiment/gateway-subscription-001)
git commit # 38cbc23 compose fixes + verifier + workflow
git push origin experiment/gateway-subscription-001
# dispatch attempts (workflow_dispatch 404s for branch-only files):
gh api -X POST repos/terryncew/openline-receipt-gate/actions/workflows/\
gateway-subscription-001-docker.yml/dispatches \
  -f ref=experiment/gateway-subscription-001   # -> HTTP 404 (x3)
# fallback: temporary path-scoped push trigger, then per-fix pushes:
git push origin experiment/gateway-subscription-001  # attempt 1: 38121276650
# fix build context -> push                        # attempt 2: 38121356866
# fix STRICT_DNS -> push                           # attempt 3: 38121652597 (cancelled)
                                                    # attempt 3r: 38121686646
# fix authz CMD + internal:true -> push            # attempt 4: 38122041694 (14/21)
gh run view <id> --log-failed
gh run download <id> -n gateway-docker-logs -D /tmp/gwlogs<N>
# final: mockapi bind fix + verifier hardening + trigger revert (committed, pushed; no CI run)
```

Final SHAs on the branch at time of writing: `bb7b945` (attempt-4
head) plus the pending final commit with the mock_api fix, verifier
hardening, workflow trigger revert, and this evidence file.

---

## 9. Coordinator follow-up: 5th and 6th runs (2026-10-11)

The step-1 agent stopped at its 4-attempt budget with the
`MOCK_API_HOST` fix committed but unverified. The coordinator took two
further runs (temporary push trigger re-added, then reverted again —
final workflow state is `workflow_dispatch`-only).

### Attempt 5 — run 38122780088 — 20/21 PASS

The `MOCK_API_HOST=0.0.0.0` fix worked: the full HTTP path through the
Dockerized stack went green — signed transfer 200, exact ±100 cent
ledger deltas, tamper/replay/revoke denials, `verify-receipts` 0
invalid, persistence across mockapi restart, full-stack restart with
receipts surviving.

Single failure: `f3 balances survive full restart` — balance reads via
Envoy returned -1 (unreadable) right after the full-stack restart.
Balance persistence itself was proven by adjacent checks (d2:
mockapi-only restart; f4: DB volume survives full restart), so this
read as a verifier readiness race: f1/f2 waited for Envoy health and
the authz chain but nothing waited for the mockapi upstream.

### Attempt 6 — run 38122910173 — 20/22 PASS (verifier fix did not help)

Added the missing wait (`f2b`: poll balance reads until 200, 90 s
budget) before the f3 assertion. It **timed out**: the mockapi
upstream stayed unreachable via Envoy for 90 s+ after the full-stack
restart, while the authz chain (f2) and receipt checks (f4) passed.
The mockapi container printed no post-restart log lines in the
captured artifacts.

This is no longer explainable as a brief readiness race. Candidate
causes (not isolated): Envoy STRICT_DNS not recovering the mockapi
upstream after a full restart, or a compose restart-ordering issue in
the packaging. NOT data loss: balances and receipts are proven
persistent by d2/f4. But the root cause is open, so the Docker path
stays **NOT fully verified**.

### Final verdict (unchanged)

**20/22 checks pass on real Docker** (`ubuntu-latest`, 6 runs). Every
product behavior the mission required passes: full HTTP path, exact
ledger effects, tamper/replay/revoke denials, persistence across
service restart, receipt verification, full-stack restart recovery of
receipts. The one gap: balance readability via Envoy after a
FULL-stack restart (90 s timeout; root cause unisolated —
Envoy-upstream-recovery vs compose restart ordering).

Per the mission's hard rule, the Docker deployment is **not described
as verified**. Recommended follow-up: reproduce the full-restart
upstream stall locally with Docker, isolate (Envoy admin
`/clusters` output post-restart would settle DNS vs container
liveness), then re-run. The temporary trigger is reverted; re-running
needs it re-added or a `main` stub (owner approval).
