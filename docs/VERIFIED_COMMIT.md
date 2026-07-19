# Verified Commit

Verified Commit is an optional authorization carried by the existing signed
`proof_to_policy_decision_receipt`. It adds no receipt family, disposition,
score, marketplace, staking mechanism, certification, or predictive claim.

## Receiver contract

The receiver places `metadata.verified_commit` in its external policy. That
policy names the approved tool and target and pins the hashes and identifiers
that must survive the handoff:

```json
{
  "required": true,
  "tool": "filesystem.write",
  "target": "artifact://approved.json",
  "settings_hash": "<64 lowercase hex>",
  "run_id": "run-123",
  "capsule_hash": "<64 lowercase hex>",
  "evidence_hashes": ["<64 lowercase hex>"],
  "max_ttl_seconds": 300
}
```

The request supplies the same action, the receiver policy hash, an expiry, and a
fresh 256-bit one-use code. The raw settings are reduced to canonical SHA-256;
the code is reduced with a domain-separated SHA-256. The signed decision stores
neither raw value.

If every normal Gate assessment and the Verified Commit assessment passes, the
existing `COMMIT` receipt carries `commit_authorization`. The authorization
binds:

```text
profile
tool
target
settings_hash
run_id
capsule_hash
evidence_hashes
policy_hash
expires_at
one_use_code_hash
action_hash
authorization_hash
```

The Python and Node decision verifiers recompute the policy hash, decision,
action hash, authorization hash, evidence/run bindings, expiry limit, and the
authorization copy inside the assessment. The trusted Gate key must still come
from receiver-controlled configuration.

## Tool boundary

`VerifiedCommitLedger.execute_once()` performs this sequence:

```text
verify signed decision against receiver key
  → require VERIFIED / COMMIT / commit_authorization
  → compare the entire attempted action
  → check receiver-held code and expiry
  → atomically reject or consume decision + code
  → record started
  → invoke callback
  → record completion or failure
```

The local ledger uses a process lock, an in-process lock, and atomic file
replacement. Failed checks are recorded with reason codes and `not_started`.
The one authorized attempt is consumed before callback invocation. If the
callback throws or the process dies after consumption, replay stays blocked.

The ledger is local enforcement state, not a new receipt and not an independent
witness. A deployment that needs cross-host coordination must place equivalent
atomic state behind every applicable tool boundary. A tool reachable without
that boundary is outside the claim.

## Demonstrated attacks

The bundled proof blocks, before execution:

- changed tool;
- wrong target;
- changed settings;
- changed run;
- changed capsule;
- changed evidence;
- changed policy;
- wrong one-use code;
- expired authorization;
- sequential replay; and
- one of two simultaneous uses.

The successful lane is a deterministic offline Model A → Model B continuity
swap followed by one receiver-approved file write. Provider/model identifiers
are declarations in that fixture; they are not evidence that commercial model
APIs ran.

## Secret handling

Generate codes with `issue_one_use_code()` or another cryptographically secure
256-bit source. Keep production codes in receiver custody. The `model-swap` CLI
accepts them only through a mode-0600 file, never as a command-line argument.
Receipt verification alone does not reveal the code or grant execution.
