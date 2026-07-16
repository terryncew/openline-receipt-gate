# Threat Model

## Defended in this release

- post-signature mutation of OLP, Agent Receipt, Pipelock ActionReceipt v1, outcome, or decision objects;
- payload-hash rewriting without the applicable signing key;
- locally resealed decision forgery that contradicts the signed policy and assessments;
- missing or altered evidence artifacts;
- evidence rebound to a different source receipt;
- outcome receipt rebound to another source;
- Agent Receipt chain gaps, issuer changes, parent mismatches, and receipts after a terminal marker;
- OLP amendment gaps, parent mismatches, and declared capture loss;
- exact source replay, nonce replay, expired challenges, cross-run binding, and wrong decision parents;
- unsigned legacy records being promoted to trusted provenance;
- request-supplied trust or policy substitution through the CLI boundary;
- an arbitrary self-signed decision being mistaken for an authorized gate decision (verifiers require an externally pinned gate key);
- duplicate JSON keys in requests, policies, trust stores, JSON evidence, session state, and decision logs;
- evidence-path traversal and symlink escape outside the request directory, plus oversized evidence above the external policy limit.
- laundering a verified Pipelock `block` action verdict into an OLP `COMMIT`;
- treating an embedded, self-consistent Pipelock signer key as externally trusted provenance.
- changing a pinned Assay archive byte or substituting an internally valid
  archive whose SHA-256 differs from the receiver declaration;
- Assay bundle path traversal, symlink escape, request-selected verifier
  execution, and oversized archives above the adapter limit;
- laundering a failed Assay Trust Basis assertion into a passing OLP source
  signal;
- silently treating successful Assay bundle verification as proof of arbitrary
  receiver-policy completeness.

## Outside this release

- a host administrator replacing the gate key, trust store, policy, ledger, and output together;
- omission before any configured capture boundary observes the action;
- collusion by every trusted witness;
- false but correctly signed statements by a trusted source or outcome witness;
- transactional recovery if a process crashes between ledger consumption and JSONL publication;
- network distribution, transparency-log anchoring, HSM/KMS custody, and key rotation;
- execution of the requested rollback;
- undetected deletion of a valid tail from a local decision JSONL without an externally retained terminal anchor.
- Pipelock EvidenceReceipt v2 and mixed v1/v2 chain verification in this phase;
- any claim that OLP inherits Pipelock's outside-agent, inline mediation boundary;
- completeness of a Pipelock ActionReceipt chain beyond the receipts actually presented.
- Assay's inline MCP policy enforcement, signed mandate authorization, eBPF/LSM
  or Landlock enforcement, and any other live execution boundary;
- omissions or false source artifacts that remain consistent with Assay's
  declared bundle and registered claim boundary;
- truth or receiver-policy correctness of an arbitrary caller-supplied Assay
  DSSE predicate merely because its signature verifies;
- Assay DSSE attestation ingestion as a source format. v0.4.0 consumes the
  verified evidence bundle and exercises attestation only as a capability
  control;
- protection when the operator substitutes the trusted Assay executable,
  receiver policy, bundle pin, OLP key, and release evidence together.

## Trust-store rule

Signature verification identifies key possession. The external trust store determines whether that key has authority for `source` or `outcome`, and records its declared custody relationship.

A self-resolving `did:key` can verify integrity without appearing in the trust store. It cannot earn provenance or outcome authority merely by resolving.

## Coverage language

Coverage is deliberately labeled as declared receipt-chain coverage. A continuous sequence through a terminal marker does not prove that every consequential real-world action emitted a receipt.
