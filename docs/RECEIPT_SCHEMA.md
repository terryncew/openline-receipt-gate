# Decision Receipt Schema

The v0.3 output is an Ed25519-signed JSON object using `olp-canonical-json-int-v1`.

The embedded public key verifies integrity but grants no authority by itself. A receiver must pin the authorized gate public key outside the receipt and supply it to either verifier.

```json
{
  "kind": "proof_to_policy_decision_receipt",
  "receipt_version": "0.3",
  "algorithm_id": "openline-proof-to-policy-gate-0.3",
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
    "outcome": {"status": "pass", "reason_codes": [], "details": {}}
  },
  "verdict": "VERIFIED",
  "decision": "COMMIT",
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

The Python and Node verifiers continue to accept signed v0.2 decision receipts.
They apply v0.2's original assessment set when recomputing those decisions.

`openline.receipt_gate.v0.1.1` remains supported and is documented by its source implementation. It is a local hash chain rather than a signed proof-to-policy decision receipt.
