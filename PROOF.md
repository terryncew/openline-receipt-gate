# OpenLine: one mechanism, two failure modes

**OpenLine controls what authority can survive into the next action.**

An AI system can fail in two opposite directions:

1. authority was valid, then something changed;
2. authority was never granted in the first place.

OpenLine handles both at the same place: the receiver-owned consequence boundary.

```text
producer / agent
      ↓
proposed effect
      ↓
receipt + evidence + current standing / mandate
      ↓
receiver-owned check
      ↓
atomic consume
      ↓
COMMIT / QUARANTINE / DENY
      ↓
effect
```

The model does not get to convert its own confidence, usefulness, or urgency into permission.

The receiver decides whether the exact consequence is still justified **at the moment it becomes real**.

That is the shared primitive. Everything below is one of two failure modes.

---

## Failure mode A: authority was good, then turned bad

A compromised agent can create downstream authority before anyone knows it is compromised.

The hard problem is not merely detecting the compromise. It is preventing the authority already created by that agent from continuing to compound after the correction arrives.

IAC-004 deliberately dispatched downstream coroutines **before** the compromise receipt. They raced concurrently toward the effect boundary.

A stale pre-check failed exactly the way a time-of-check/time-of-use system can fail: authority was checked while still valid, execution yielded, the correction arrived, and the old authorization was still used later.

### CI result

| Arm | Post-correction tainted result | Clean work |
|---|---:|---:|
| No propagation | 1,141 / 1,141 escaped | 100% committed |
| Stale pre-check | 692 / 1,833 escaped — **37.7523%** | 100% committed |
| Global kill | 0 escaped | **44.1406%** committed |
| Atomic receiver gate | **0 / 1,140 escaped** | **100% committed** |

The atomic gate did not merely check earlier and hope nothing changed.

Correction application and effect authorization contended on the same receiver-owned linearizable boundary.

```text
stale pre-check

CHECK: valid
   ↓
scheduler gap
   ↓
CORRECTION ARRIVES
   ↓
old permission reused
   ↓
COMMIT   ← escaped


atomic receiver gate

scheduler / already-dispatched work
   ↓
receiver boundary
   ↙            ↘
CORRECTION      EFFECT
   \            /
    same atomic boundary
           ↓
      current standing
           ↓
       BLOCK / COMMIT
```

**Earned standing:** `UNWARE_RUNTIME_RACE_CONTAINMENT`  
**Policy authority:** `NONE`

Evidence:

- [IAC-004 protocol and claim boundary](benchmarks/inherited-authority-containment-004/README.md)
- [IAC-004 GitHub Actions receipt](https://github.com/terryncew/openline-receipt-gate/actions/runs/32617638468)
- CI artifact: `iac004-race-evidence`, artifact ID `9487424028`
- [Verified Commit receiver contract](docs/VERIFIED_COMMIT.md)

What this does **not** prove:

- arbitrary code can be preempted before it reaches the receiver boundary;
- completed effects can be undone;
- cloud credentials are automatically revoked;
- compromise detection is solved;
- every runtime is covered.

The narrow result is stronger because it is smaller:

> **Already-dispatched concurrent work raced the correction toward effect. At the atomic receiver boundary, no post-correction tainted effect escaped.**

---

## Failure mode B: authority was never granted

The opposite failure is quieter.

An agent can discover something useful to do that the user never authorized.

That can look like good reasoning:

- disclose an extra medical record because it may strengthen an appeal;
- accept a settlement because the agent thinks the offer is attractive;
- delegate to another system because it looks efficient.

Usefulness is not authority.

Mandate Gate adds a reusable principal mandate over the existing Verified Commit consequence machinery.

```text
principal mandate
      ↓
purpose
allowed actions
allowed disclosures
forbidden disclosures
settlement / payment ceilings
delegation ceiling
expiry
      ↓
exact proposed effect
      ↓
Mandate Gate
      ↓
Verified Commit
      ↓
one-use atomic execution
```

The medical-bill demo makes the distinction visible with the same proposed action in guarded and unguarded paths.

### CI result

```text
NO GATE       psychiatric record proposal -> SENT
MANDATE GATE  same proposal -> BLOCKED

ALLOWED       billing record + EOB -> SENT
SETTLEMENT    $500.01 proposal -> BLOCKED
MODEL SWAP    authority unchanged
REPLAY        spent authorization -> BLOCKED
RACE          16 concurrent attempts -> 1 effect
PRESSURE QA   128 / 128 hostile proposals held
```

The pressure batch contains 64 varied embedded-document pressure phrasings across two producer-model labels.

It is deliberately a **downstream structured-effect pressure test**, not a claim that two live language models resisted prompt injection. The producer is allowed to propose the forbidden consequence. The receiver still refuses to authorize it.

**Earned standing:** `PRINCIPAL_MANDATE_CONSEQUENCE_ENFORCEMENT`  
**Policy authority:** `NONE`

Evidence:

- [Mandate Gate 002 consequence-boundary protocol](benchmarks/mandate-gate-002/README.md)
- [Medical Bill Mandate Demo](demos/medical-bill-mandate-demo/README.md)
- [Medical Bill Demo GitHub Actions receipt](https://github.com/terryncew/openline-receipt-gate/actions/runs/32620481357)
- CI artifact: `medical-bill-mandate-demo-evidence`, artifact ID `9488222420`
- [Verified Commit receiver contract](docs/VERIFIED_COMMIT.md)

What this does **not** prove:

- software creates a legal fiduciary duty;
- real medical records were used;
- real money moved;
- a model cannot be manipulated;
- every possible semantic mandate can be expressed.

The tested claim is downstream:

> **The AI may propose an unauthorized consequence. The receiver can still refuse to make it real.**

---

## The same mechanism

These are not two products.

They are the two sides of the same authority problem.

```text
                AUTHORITY AT CONSEQUENCE TIME

      authority existed                     authority never existed
      but lost standing                      for this consequence
             │                                      │
             ▼                                      ▼
      compromise / recall                    mandate boundary
      evidence withdrawal                    disclosure ceiling
      changed dependency                     value ceiling
             │                                      │
             └──────────────┬───────────────────────┘
                            ▼
                  receiver-owned appraisal
                            ▼
                   atomic consequence gate
                            ▼
              COMMIT / QUARANTINE / DENY
```

**IAC asks:** what should stop being trusted after a correction?

**Mandate Gate asks:** what was never authorized to become trusted in the first place?

Both terminate at the same rule:

> **Do not let yesterday's permission—or somebody else's idea of permission—silently become today's consequence.**

---

## Why the atomic boundary matters

Portable proof is useful, but a verified historical fact is not itself permission.

A receipt can remain cryptographically valid while the authority it once justified is gone.

Likewise, a model can produce an excellent recommendation without possessing the user's permission to execute it.

That is why OpenLine separates:

```text
proof that something happened
        ≠
evidence that still stands
        ≠
permission for this exact action
        ≠
permission to execute it more than once
```

Verified Commit binds the exact tool, target, settings hash, run, evidence, policy, expiry, and one-use code, then atomically consumes the authorization before invoking the consequence.

The receiver owns the last word.

---

## The public claim

OpenLine is not a compromise detector, an IAM replacement, a prompt-injection detector, or a legal fiduciary relationship.

It is a receiver-owned verification and consequence layer.

Its current evidence supports two narrow statements:

> **When authority becomes bad, OpenLine can stop it from continuing to compound at a receiver-owned consequence boundary.**

> **When authority was never granted, OpenLine can stop an agent's useful-looking proposal from becoming an authorized consequence.**

That is the mechanism.

Everything else is an application.
