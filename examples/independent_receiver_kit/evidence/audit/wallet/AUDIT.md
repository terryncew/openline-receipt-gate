# Wallet read-only audit: INDEPENDENT-RECEIVER-001

Audited `terryncew/openline-wallet` main, exact revision `f309aac8aecae36c4f354c7455281af6dbce486a` (`docs: publish OpenLine Wallet attribution and citations (#54)`). The isolated inspection checkout is `/tmp/openline-wallet-source-audit`; no Wallet source changes, commits, or pushes were made. Receipt Gate comparison revision is `81db6acb72149df989aac1827e5f621b0873d57b`.

## Actual CLI contract

`pyproject.toml:29` declares `openline-wallet = openline_wallet.cli:main`. The CLI commands are init, keygen-subject, grant, narrow, revoke, show, history, export, import, verify, record, and demo-platform-exit (`src/openline_wallet/cli.py:21`). No Receipt Gate owner-authorization export command exists in the inspected CLI.

`export [--output PATH] [--ttl 10m]` emits a JSON `openline.wallet.receiver_bundle.v1` signed by the Wallet root key (`cli.py:63`, `cli.py:219`, `wallet.py:762`). It carries principal/root, root-signed epoch certificate, epoch-signed event timeline, receiver receipts, timeline head, issue/expiry times, canonicalization, and authority declarations. Maximum and default export TTL is 600 seconds (`wallet.py:34-40`). Export excludes private keys.

`verify FILE [--allow-expired] [--json]` invokes `verify_bundle` and returns `EVIDENCE_VALID`, not action permission (`cli.py:149`). The JSON explicitly reports `wallet_policy_authority: NONE`, `decision_authority: RECEIVER_GATE` (`cli.py:157`). `--allow-expired` is evidence-history inspection and bypasses freshness only; it is not permission to perform an effect.

## Verification and trust boundaries

`wallet.py:368` verifies exact bundle schema/shape, principal ID as a hash of root public key, root signature, canonicalization/authority declarations, bounded bundle TTL and current freshness, event replay and declared head, and receipt signatures. Its root comes from the bundle: this proves internal consistency/authorship, not that the root is a locally trusted owner.

`wallet.py:203` replays the epoch certificate and contiguous signed events. `wallet.py:165` defines mandate data as mandate_id, subject_id, subject_public_key, scopes, expiry, and predecessor_mandate_id. Narrowing preserves subject/key, strictly reduces scope and/or expiry, revokes/supersedes prior standing; revocation changes status. There is no `principal_mandate/v1` effect-policy object or `openline.mandate_owner_authorization.v1` record in this representation.

The included Wallet `ReferenceGate` separately pins a principal/root (`receiver.py:119`), admits only fresh monotonic compatible histories and quarantines forks (`receiver.py:162`), issues a challenge bound to principal/subject/action (`receiver.py:207`), and requires a subject signature, current admitted history, current mandate status/expiry, exact action scope, and one-use challenge (`receiver.py:291`). `create_presentation` signs a challenge/action/head binding using the subject key (`receiver.py:42`). This reference gate signs decisions and performs no side effect itself (`receiver.py:74`). Its frontier, quarantine, challenges, and receipt replay sets are in-memory dictionaries/sets (`receiver.py:108`); these are not restart-durable in the base class.

Receipt validation inside Wallet (`wallet.py:325`) verifies receipt shape, principal, decision, and signature against the key carried in that receipt; the standalone evidence verifier does not assert the receiver key belongs to a receiver trusted by an external verifier. A receiving deployment needs a separate gate-key trust policy.

## Receipt Gate compatibility

The cryptographic envelope is compatible: Ed25519 over `olp-canonical-json-int-v1` bytes, SHA-256 payload hash, and signature {algorithm, public_key, value}. Compare Wallet `crypto.py:64`, `canonical.py:80` with Receipt Gate `olp_gate/crypto.py:87`, `olp_gate/crypto.py:180`.

The authority schemas are not directly interoperable. Receipt Gate `olp_gate/mandate.py:44` requires the richer `principal_mandate/v1` object (principal/agent/purpose/action types/targets/disclosure classes/limits/delegation/expiry/version). `olp_gate/mandate_owner.py:144` issues an explicit owner-signed lifecycle authorization bound to its mandate hash, configured slot, owner, state, sequence, predecessor and lifetime. `MandateOwnerView` (`mandate_owner.py:552`) pins owner keys in receiver configuration and admits lifecycle records (`mandate_owner.py:705`) rather than treating developer-authored proposals or generic signed Wallet exports as governing authority.

**Scope limit:** Wallet export is sufficient portable evidence input for an independently implemented receiver policy that explicitly recognizes Wallet's bundle/profile. It is not an existing Wallet CLI path producing Receipt Gate MandateOwnerView records. Deriving an owner authorization with a receiver-held key would create different authority and must not be described as the Wallet owner signing it. A compatibility bridge must preserve the original signed bundle, pin its owner root, verify its full timeline and subject proof, and openly specify any receiver-owned policy mapping. It cannot invent richer mandate semantics from opaque scope names.

## Executed proof

`/tmp/wallet-audit-evidence/run.py` invoked actual CLI init/keygen/grant/export/verify through the unchanged source using PYTHONPATH. Logs: `cli-log.json`. It generated only audit-local fixture state under `/tmp/wallet-audit-evidence/wallet` and keys under `/tmp/wallet-audit-evidence`; do not copy private files into evidence.

The exported artifact `wallet.olw` SHA-256 is `e3eacc3a9a415dc30f023a76a8ead2544bdf75804a661feafea5b59e02a1a6bd`. `compatibility-proof.json` records that actual CLI verification returned EVIDENCE_VALID, Receipt Gate `verify_olp_signature(bundle)` returned `(true, null)`, while `validate_mandate_authorization(bundle, ...)` rejected it with exact reason `mandate_authorization_shape_invalid`. This is a reproduced compatibility gap, preserved before any Receipt Gate implementation.

Authoritative source links use the pinned Wallet revision: `https://github.com/terryncew/openline-wallet/blob/f309aac8aecae36c4f354c7455281af6dbce486a/src/openline_wallet/{cli,wallet,receiver,crypto,canonical}.py`.
