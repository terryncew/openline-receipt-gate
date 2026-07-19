# Decision Receipt Schema

The v0.4 output is an Ed25519-signed JSON object using `olp-canonical-json-int-v1`.

The embedded public key verifies integrity but grants no authority by itself. A receiver must pin the authorized gate public key outside the receipt and supply it to either verifier.

```json
{
  "kind": "proof_to_policy_decision_receipt",
  "receipt_version": "0.4",
  "algorithm_id": "openline-proof-to-policy-gate-0.4",
  "canonicalization_id": "olp-canonical-json-int-v1",
  "issuer": {"id": "procurement-gate"},
  "created_at": "2026-07-12T00:00:00Z",
  "request_id": "request-123",
  "action": {
    "type": "tool_call",
    "id": "act-123",
    "risk_level": "medium",
    "claim_hash": "sha256 without prefix"
  },
  "source": {
    "format": "agent_receipts",
    "receipt_hashes": ["..."],
    "primary_hash": "...",
    "source_key_ids": ["did:example:agent#key-1"]
  },
  "binding": {
    "run_id": "run-123",
    "session_id": "session-123",
    "sequence": 1,
    "challenge_nonce": "...",
    "parent_decision_hash": null,
    "expected_source_hash": "..."
  },
  "policy": {
    "id": "tool-policy",
    "version": "1",
    "hash": "...",
    "snapshot": {}
  },
  "assessments": {
    "integrity": {"status": "pass", "reason_codes": [], "details": {}},
    "profile": {"status": "pass", "reason_codes": [], "details": {}},
    "provenance": {"status": "pass", "reason_codes": [], "details": {}},
    "independence": {"status": "pass", "reason_codes": [], "details": {}},
    "coverage": {"status": "pass", "reason_codes": [], "details": {}},
    "source_signal": {"status": "pass", "reason_codes": [], "details": {}},
    "freshness": {"status": "pass", "reason_codes": [], "details": {}},
    "evidence": {"status": "pass", "reason_codes": [], "details": {}},
    "outcome": {"status": "pass", "reason_codes": [], "details": {}},
    "verified_commit": {
      "status": "pass",
      "reason_codes": [],
      "details": {
        "required": false,
        "profile": "verified_commit/v1"
      }
    }
  },
  "verdict": "VERIFIED",
  "decision": "COMMIT",
  "commit_authorization": null,
  "chain_accepted": true,
  "reason_codes": [],
  "privacy": {
    "raw_evidence_stored": false,
    "raw_source_disclosure_stored": false
  },
  "payload_hash": "...",
  "signature": {
    "algorithm": "Ed25519",
    "public_key": "32-byte lowercase hex",
    "value": "64-byte lowercase hex"
  }
}
```

When receiver policy requires exact tool permission and every check passes,
`verified_commit.details.required` is `true` and `commit_authorization` is:

```json
{
  "profile": "verified_commit/v1",
  "tool": "filesystem.write",
  "target": "artifact://approved.json",
  "settings_hash": "<64 lowercase hex>",
  "run_id": "run-123",
  "capsule_hash": "<64 lowercase hex>",
  "evidence_hashes": ["<64 lowercase hex>"],
  "policy_hash": "<64 lowercase hex>",
  "expires_at": "2026-07-18T12:05:00Z",
  "one_use_code_hash": "<domain-separated 64 lowercase hex>",
  "action_hash": "<64 lowercase hex>",
  "authorization_hash": "<64 lowercase hex>"
}
```

The same authorization appears inside the signed Verified Commit assessment so
both verifiers can reject inconsistent resealing. Raw settings and the raw
one-use code are absent from the signed receipt. `commit_authorization: null`
means the decision grants no portable tool permission even when the decision is
`COMMIT`.

## Verdict and enforcement are separate

```text
VERIFIED     enough supported proof for the declared policy
REJECTED     a declared check failed
UNDECIDABLE  required information is unavailable or only partial
```

The enforcement decision maps the verdict into the operational surface:

```text
COMMIT
QUARANTINE
DENY
NO_BADGE
ROLLBACK_REQUEST
```

## Legacy schema

The Python and Node verifiers continue to accept signed v0.2 and v0.3 decision
receipts. They apply each version's original assessment set when recomputing
those decisions and reject a Verified Commit authorization on a legacy version.

`openline.receipt_gate.v0.1.1` remains supported and is documented by its source implementation. It is a local hash chain rather than a signed proof-to-policy decision receipt.
