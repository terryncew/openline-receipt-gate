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
