# OPENLINE-GATEWAY-001: Failure Record

Every failure encountered during the build, recorded without
modification. A failure fixed is still a failure.

## 1. /tmp wipe destroyed uncommitted work (2026-10-10)
Built the entire vertical slice in /tmp/rgw. A VM restart wiped /tmp
including the git clone. Nothing had been committed. Rebuilt from
scratch in ~/workspace/repos (durable). Lesson re-learned: the
workspace's own AGENTS.md already documented this; violated anyway.
Cost: ~2 hours of rebuild.

## 2. CheckResponse.ok_response field number (2026-10-10)
Defined `ok_response = 2` in the minimal ext_authz proto. Envoy's real
proto uses `ok_response = 3` (`denied_response = 2`). Result: requests
were authorized (status.code=0 honored) but `has_ok_response()` was
false, so Envoy silently dropped the decision headers. Diagnosed via
Envoy trace logs + source reading. Fixed; regression test added
(`test_ok_response_field_number`).

## 3. Mandate effect profile string (2026-10-10)
Used `principal_mandate_effect/v1` as the effect profile;
`olp_gate` requires `principal_effect/v1` for effects
(`principal_mandate_effect/v1` is the *settings* profile). All requests
denied with `effect_profile_invalid` until fixed.

## 4. Missing effect fields (2026-10-10)
`validate_effect` requires exactly 12 fields including `effect_id`
and `producer_model`. First version omitted them; denied with
`effect_shape_invalid`.

## 5. PID file concatenation (2026-10-10)
Scenario restarts wrote PIDs without truncating reliably, producing
concatenated PID files and orphaned servers holding :50051. Replaced
with `restart_authz()` helper that kills, waits for port release,
verifies bind, then writes.

## 6. OPA envoy plugin absent (2026-10-10)
Stock OPA 1.10.1 binary does not bundle the envoy gRPC plugin; no Go
toolchain to build it. Used a gRPC→REST shim instead. The decision
logic remains 100% Rego; the shim is protocol translation only.
Documented in ARCHITECTURE.md.

## 7. Scenario 13 flake (2026-10-10)
Observe-mode test failed because a stale server held the port after a
botched restart (see #5). Fixed by the same helper.

## Open (not failures, but unresolved)
- Docker Compose path not tested here (no Docker on this VM); the
  compose files are written but unverified. An independent engineer
  with Docker is the real test.
- Latency optimization (WAL mode, batched commits) noted but not
  applied; numbers reported as measured.

---

# GATEWAY-SUBSCRIPTION-001 failures (2026-10-11)

Same rule: recorded without modification. A failure fixed is still a
failure.

## 8. Compose config volume starts empty (2026-10-11)
The `gateway-config` named volume is empty on first boot; authz and
mock API crash with FileNotFoundError on missing receiver.key /
policy.json. The compose path could never have worked as written.
Fixed with `compose/entrypoint-gateway.sh` (runs `gateway_admin.py
init` on first boot, mkdir-locked against the concurrently booting
services). Found by actually running it on a GitHub Actions runner.

## 9. Envoy in-container 127.0.0.1 (2026-10-11)
`envoy-openline.yaml` points upstreams at 127.0.0.1 — inside the Envoy
container that is the container itself, not the authz/mockapi
services. Added `compose/envoy-openline-compose.yaml` with
service-name endpoints (`authz:50051`, `mockapi:9000`); the host-mode
file is untouched so `./up.sh` keeps working.

## 10. provision-agent --max-cents silently ignored (2026-10-11)
The space form `--max-cents 5000` was silently ignored, provisioning
the default 10000 instead of 5000. Only `--max-cents=5000` worked.
Real product bug in the admin CLI; fixed to accept both forms.

## 11. Python grpc client vs IPv4 localhost (2026-10-11, environment)
Direct gRPC `Check` calls from the Python grpc client to 127.0.0.1
fail 100% with "Failed parsing HTTP/2 (got frame type 101)" on this
VM — reproduced with a bare grpc server, so not a gateway defect. Raw
TCP and Envoy's C++ ext_authz client over 127.0.0.1 are fine.
Workaround: connect to `[::1]` (the server binds `[::]` dual-stack).
Affects dev/test tooling only. Recorded, not hidden.

## 12. Burst-correlated RSTs on IPv4 loopback (2026-10-11, environment)
Under 20-thread connection bursts, ~5–20% of requests die with
ConnectionResetError/RemoteDisconnected on this VM; a bare
HTTPServer control shows the same class of flake. Every affected
token retried cleanly — the RST lands before the commit, never a
phantom execution; ledger reconciliation held in all rounds.
Transport flake, not a product defect.

## 13. Coordinator killed a sibling agent's test process (2026-10-11)
While debugging, the coordinator ran `pkill -f "authz_server.py
50051"`, which matched another worker's test stack. Lesson: never
pattern-kill shared ports; scope kills to PIDs your own scripts
started (the demo's run_demo.sh already does this via its PID list).
The affected worker confirmed its runs were not impacted (failures
predated the kill, suite green before it).

## 14. Debug-copy instrumentation bug (2026-10-11, harness)
A `str.replace` on a throwaway /tmp copy of mock_api.py matched
inside a longer indented line and dedented a `return` to method
level. The repo file was never affected; the copy was discarded.
Lesson: instrument copies with AST or diff-review, not blind replace.

## Open (subscription mission)
- The 60 s post-revocation token window is narrowed, not closed:
  with the standing check, the residual is the check-to-commit
  interval (p50 ~1.4 ms, max 35.6 ms measured, n=30); without it,
  tokens execute to their 60 s TTL. No instant-revocation claim.
- The mandate model has per-charge caps but no per-period recurrence
  limit; "monthly" is the billing narrative, not an enforced parameter.
- Docker Compose verification runs on the GitHub Actions runner; see
  `gateway/subscription001/EVIDENCE-docker.md` for its status.
