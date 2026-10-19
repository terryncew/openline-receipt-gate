# Wallet receiver interoperability — pre-implementation finding

Pinned receiver base: 76f72ccccce79622f40163763cf614bd1d7ff776.
PR #121 implementation: 4d8565c844a26ad703a8f82332c1e18ec8acb5c1; current main ships the lean kit in PR #125.
Pinned Wallet: f309aac8aecae36c4f354c7455281af6dbce486a.
Pinned Wire Canon: 3607996396e4a647213a4a67bc62d4ae07f998f4.

No AGENTS.md exists in the recursive trees of these three pinned repositories. Receiver NORMAL_WORKFLOW.md governs a separate Jain benchmark; that benchmark is untouched. Wallet SECURITY.md, README, receiver.py, wallet.py, canonical.py and test_receiver.py were inspected. The receiver kit EVALUATION.md, original PR #121 README/REPORT and compatibility evidence were read. No Wallet, canonical, Muse proof-package or Gemini research file will be changed.

The native kit expects exactly {mandate, authorization}; authorization must be openline.mandate_owner_authorization.v1 and bind a principal_mandate/v1 hash, owner slot, sequence and predecessor. An unwrapped Wallet export fails head_packet_shape_invalid; passing that signed export as authorization fails mandate_authorization_shape_invalid. A valid outer Ed25519 signature does not establish native mandate-profile validity.

Wallet's export is openline.wallet.receiver_bundle.v1: the independently pinned principal root signs the bundle and certifies an epoch key; epoch-signed issue/narrow events and root-signed revoke events form a complete hash-linked timeline. Grants sign subject ID/key, opaque exact scopes, expiry and predecessor mandate. Wallet policy authority NONE means Wallet cannot decide receiver policy; it does not erase those signed grants. verify_bundle verifies evidence but accepts the embedded root for cryptographic self-consistency; receiver trust must additionally pin that root outside the packet.

Wire Canon SPEC.md defines canonical bytes and capture receipt semantics, not permission to convert one authority profile into another. No receiver-signed replacement owner credential is permitted.

Planned bounded adapter: preserve the original signed bundle object as authority evidence (JSON transport formatting may differ); verify with unmodified pinned Wallet library and external root pin; project verified fields into the kit's internal head view. Exactly one receiver-defined operation is mapped from the explicitly signed scope intake.submit:records://local-lab/intake. No money, disclosure or delegation. Purpose uses that exact signed scope string; it is not inferred from prose. The last signed timeline event selects this single receiver slot, conservatively excluding other simultaneous grants. Receiver policy remains an additional restriction.

The original native/JWT modes must remain unchanged. New Wallet mode must retain monotonic history, fork quarantine, no freshness renewal from identical heads, fresh exact worker proof, atomic SQLite nonce/effect/decision commit, and independent replay. Fresh owner exports with a different head are separate admission attempts. Unsupported/bad authority must never manufacture missing signed intent.

Equivalent baseline: owner root issues conventional EdDSA JWT authorization over the same selected subject/scope/expiry/lifecycle, using the same root and worker keys, receiver policy/freshness and commit/evidence path. JWT is issued by the fixture owner, never by the receiver. Wallet additionally verifies its epoch/timeline signatures; that representation overhead is disclosed rather than described as superiority.
