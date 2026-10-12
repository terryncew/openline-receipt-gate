# Fair Economic Comparison: OpenLine vs. Stateful Envoy/OPA

**OPENLINE-RECEIVER-001 Priority 4.** Technically fair: a capable team
*can* build these protections from Envoy + OPA + custom services. The
question is what it costs — in latency, in installation burden, in
operational dependencies, and in ongoing ownership.

## The approaches

| | OpenLine gateway | OPA-A (ordinary) | OPA-B (stateful) |
|---|---|---|---|
| **What it is** | Envoy + OpenLine authz service (Python) + sqlite | Envoy + OPA + gRPC→REST shim | OPA-A + Data API state + revocation writer |
| **Policy** | Mandate evaluation (olp_gate) at consequence time | Rego policy | Rego + external data |
| **Replay protection** | Built in (sqlite nonce store) | None | None (or custom) |
| **Decision binding** | Signed single-use tokens (built in) | Trusts header from shim | Trusts header from shim |
| **Receipts** | Signed, in sqlite (built in) | None | OPA decision logs (unsigned) |
| **Revocation** | Registry + per-request check (built in) | None | Data API writes (external writer) |
| **Portable authority** | Wallet bundles (P2: vendored contracts) | N/A | N/A |

## Latency cost (measured)

From `gateway/bench/HEAD-TO-HEAD.md` (test VM, real Envoy):

| Approach | p50 | p90 | p99 | min |
|----------|-----|-----|-----|-----|
| OpenLine | 218.3 ms | 258.9 ms | 283.5 ms | 194.7 ms |
| OPA-A | 76.4 ms | 89.0 ms | 119.2 ms | 70.6 ms |

**OpenLine overhead: ~140 ms p50** vs. OPA-A. Dominated by durable
sqlite writes per Check (nonce store + signed receipt, ~42 ms
in-handler). The rest is Python gRPC + mandate evaluation.

**What the overhead buys:** replay protection, signed decision tokens,
signed receipts, and revocation checks — none of which OPA-A provides.
OPA-B (stateful) would add Data API latency on top of OPA-A's baseline.

**Standing check (optional):** narrows the authz→execution race from
60s (token TTL) to ~1-36ms check-to-commit (measured, n=10). Fail-closed.
See `gateway/docs/STANDING-CHECK.md`.

## Installation burden

**OpenLine (3 steps):**
1. `gateway_admin.py init` (creates key, policy, DB)
2. Provision agents (`gateway_admin.py provision-agent`)
3. `make quickstart` or `docker compose --profile openline up`

One policy file, one key file, one sqlite DB. Backup = copy two files.

**OPA-A (5 steps):**
1. Write Rego policy
2. Start OPA server
3. Start gRPC→REST shim (~90 lines, custom)
4. Configure Envoy for OPA
5. Start mock API in OPA mode (trusts header)

3 components, 5 steps, no replay protection, no receipts, no revocation.

**OPA-B (8+ steps):**
OPA-A steps, plus:
6. Seed `valid_tokens` / `revoked_tokens` via Data API
7. Configure decision logging
8. Write the revocation runbook: who calls the Data API, on what
   trigger, with what staleness bound, and what happens when the
   writer is down.

The revocation writer is a **new operational dependency** with its own
failure modes. If it stops writing, revocation stops propagating —
silently.

**"Build it all" (weeks):**
To match OpenLine's protections on OPA: build a nonce store (Redis/DB
+ code), a token minting service (signing + verification), a receipt
pipeline (signing + storage), and idempotent application logic. Then
own all of it forever: backups, monitoring, key rotation, incident
response.

## Operational dependencies

| Approach | External deps | Backup | Failure modes |
|----------|--------------|--------|---------------|
| OpenLine | None | Copy 2 files | sqlite corruption (standard) |
| OPA-A | None | Policy file | None beyond OPA |
| OPA-B | Revocation writer | Policy + Data API dumps | Writer down = revocation stops; Data API lag = stale decisions |
| Build-it-all | Nonce store, signer, receipt store | Each separately | Each component's failures, plus integration bugs |

## The Wallet portability (P2) — no OPA equivalent

OPA has no concept of portable authority. A mandate issued by an
owner's Wallet, verified by a separately operated receiver using pinned
trust, with worker replacement and freshness-bounded revocation — this
is not something you can bolt onto OPA with a Rego policy. You'd need
to build the entire bundle/presentation/challenge protocol (see
`gateway/receiver-kit/TRUST-MODEL.md`).

The P2 demo (`gateway/demo_wallet_integration.py`, 10/10) shows:
- Owner grants → receiver admits → worker allowed
- Revocation → old proofs stale, new proofs denied
- Worker replacement → same mandate, same permissions, new key

## Why a security engineer would choose OpenLine

Not because OPA "can't" do it. A capable team can build all of this.
Choose OpenLine when:

1. **You want the protections without building them.** Replay protection,
   signed tokens, signed receipts, revocation, and portable authority
   are built in, not bolted on. The 140ms overhead is the price of not
   building and maintaining those systems yourself.

2. **You need evidence, not just decisions.** OPA tells you what it
   decided. OpenLine gives you signed receipts proving what happened,
   which you can verify independently and present to auditors, owners,
   or courts.

3. **Authority must survive worker replacement.** If your agents change
   models, rotate keys, or get replaced, OpenLine's portable mandates
   mean you don't rebuild the authorization layer. OPA's policies are
   tied to whatever identity system you built around them.

4. **You want the revocation bound to be explicit.** OpenLine's
   freshness bounds (bundle age, challenge TTL, token TTL) are
   configured and enforced. OPA-B's revocation staleness depends on
   your Data API writer, which is your code and your problem.

## Why you might NOT choose OpenLine

- **140ms is too much.** If you're doing high-frequency trading or
  sub-10ms API responses, the sqlite writes will hurt. (The overhead
  is dominated by durability; a future version could offer async
  receipts.)
- **You already built it.** If you have a working nonce store, token
  service, and receipt pipeline, OpenLine doesn't add much.
- **You don't need the evidence.** If "allow/deny" is enough and no one
  will ever ask "prove it," OPA-A is simpler and faster.
- **Python in the request path.** The authz service is Python. If your
  policy needs to be in Rego for organizational reasons, OPA fits better.

## Bottom line

The product thesis is **burden, not capability**. OpenLine doesn't do
things OPA can't — it does things most teams won't build, verify, and
maintain themselves. The 140ms and the 3-step install are the price;
the signed evidence and portable authority are what you get.
