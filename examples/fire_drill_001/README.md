# The OpenLine Fire Drill

**Fire the agent. Keep the work. Prove both.**

**One disposable test. Three questions. Independent evidence.**

Can you fire an AI agent and actually stop it? Can approved work continue with a successor? Can another developer verify what the receiver actually did?

This is **OPENLINE-FIRE-DRILL-001**, a challenge prototype—not a production tool, certification, drop-in integration for arbitrary agents, or claim that competitors fail. It uses **scripted workers, a localhost HTTP receiver, disposable SQLite databases, and public test keys**, with **$0 paid API usage**. No real Claude, Codex, payment, customer file, production credential, network destination beyond loopback, or unsupervised agent is involved.

## Run it yourself

Requires Python 3.10+ and Git. From Draft PR branch `feature/openline-fire-drill-001-20261020`, based on existing ADOPTION-001 Receipt Gate code. Use a fresh disposable output directory.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . -r examples/independent_receiver_kit/requirements.txt
.venv/bin/python -m examples.fire_drill_001.run --out /tmp/my-fire-drill
sha256sum /tmp/my-fire-drill/MANIFEST.json
.venv/bin/python -m examples.fire_drill_001.verify --bundle /tmp/my-fire-drill \
    --expected-sha256 THE_MANIFEST_SHA256_FROM_ABOVE
```

Open `/tmp/my-fire-drill/fire-drill-40s.html` in a browser. It **autoplays a 40-second demonstration**, not an MP4 or fabricated terminal recording. Every effect count shown is read from the generated experiment decisions. Press **Replay 40s** to restart.

The portable evidence is the **entire `/tmp/my-fire-drill` directory**: manifest, exact HTTP request/decision journal, both signed receiver SQLite ledgers, exposed weak-mode SQLite rows, independent unrelated authority slot, one explicitly unprotected SQLite store per mode, generated presentation and provenance/limits. You can tar it and give it to someone else. Give the **SHA-256 of MANIFEST.json separately**; a manifest inside a replaceable archive cannot establish external custody or prove that the original operator was honest. No fixture private signing seed is bundled.

A verifier should invoke its own Python environment on the original bytes with a separately supplied expected manifest hash, never trust `runner_report.json` alone. The verifier does **not** import the runner, and uses the existing Receiver Kit's independent signed-decision/SQLite-effect replay verifier for the **properly secured conventional EdDSA JWT** and OpenLine modes. It checks the outcomes in the intentionally weak arm only against unsigned local rows and labels their evidentiary status accordingly. This is still **test fixture trust**: the source keys are publicly known and a sufficiently privileged operator could manufacture consistent receipts. A signed receiver decision authenticates testimony against a chosen key; it cannot prove all unobserved effects did not occur.

## The three distinct configurations

| Configuration | What it is | What counts as independently checked |
|---|---|---|
| **Intentionally weak shared credential** | A purposefully permissive *teaching counterexample*, with no actor-specific revocation and a reachable raw route; **not a named product or competent competitor** | Actual local SQLite rows; responses and actor attribution are unsigned |
| **Conventional EdDSA JWT** | The existing independent Receiver Kit's correctly configured JWT verification, exact worker possession, signed current authorization, replay and bound receiver policy | Existing independent verifier checks signed decision history, authority, replay and local effects |
| **OpenLine** | The same independent Receiver Kit using native OpenLine signed authorizations and worker-bound exact effects | Existing independent verifier performs equivalent checks and local effect reconciliation |

JWT is **not weakened**. Both strong arms receive equivalent actions, the same revocation/replacement schedule and the same after-revocation probes. A strong conventional control is **expected to pass**. The weak arm is explicitly not the commercial comparator.

The drill sends fourteen labeled HTTP requests per mode, covering an initial approved document and identical replay, signed revoke-A, old A's new effect attempts, exact replay, reused credentials, an unguarded-route probe, attempted old-authority rollback, replacement with B and successor work, stale A after replacement, plus a **genuinely separate authority slot with independent receiver ID** that remains active. No agent prose can create a signed receiver receipt. The 40-second demonstration is a *playback of the completed verified run*, not the duration of each live API/security evaluation.

## The intentionally uncomfortable result

At the receiver boundary, both properly secured systems are expected to stop the revoked A while still allowing B to complete approved work and a distinct unrelated signed permission to remain usable.

But **all three arms also write exactly one record into a separate unprotected SQLite database after revocation**. That direct path **never traverses either secure receiver**, so neither system can claim to have stopped it. Its effects are counted separately from protected effects and its actor/time attribution remains local and unauthenticated. It demonstrates a real boundary gap in this disposable topology, not a universal exploit against OpenLine/JWT.

This is a controlled receiver experiment. If a worker retains unrestricted OS file access, credentials, shell or a network route bypassing the receiver, those actions **are not controlled** merely because the HTTP receiver denies requests. Revocation unknown to the receiver until admitted is also not tested. There is no universal zombie-agent kill switch or mid-execution cancellation here.

## $0 verification and adversarial tests

```sh
.venv/bin/python -m unittest examples.independent_receiver_kit.test_receiver -v
.venv/bin/python -m unittest examples.fire_drill_001.tests -v
.venv/bin/python -m examples.fire_drill_001.verify --bundle /tmp/my-fire-drill
```

Adversarial tests remove evidence, corrupt signed decisions, rehash a tampered archive, forge a summary, erase the unprotected effect, add unlisted bytes, and attempt to turn weak assertions into verified claims. Any incomplete, mismatched, or unverifiable bundle fails closed.

## What the Fire Drill does *not* know

**Arbitrary agent compatibility:** A developer's own agent can be evaluated only if we independently confirm it can be bound to a receiving service we control and can enumerate protected **and unprotected** effect paths. There is no honest one-minute universal adapter. This test is not a model security benchmark over unknown agent environments.

**Outcome completeness:** The verifier independently checks *recorded* signed HTTP decisions and saved SQLite effects, not every possible side effect, hidden tool, operator omission, original server honesty or independently owned production system.

**Good work:** The synthetic previous `job-before` effect is preserved and B's `job-successor` effect is recorded. It is **not proof that B completed arbitrary coding requirements or that all assertions in a handoff were true**. Unrelated standing refers to another signed owner slot and receiver, not magic permission recovery.

**Comparison and distribution:** A competent conventional receiver also passes. We have not established OpenLine superiority, independent developer setup time, adoption, buyer need, revenue, or field-specific integrations. Outsider testing and outreach require a separate approval; no public launch here.

See `HANDOFF.md` for exact branch scope/results and `DEMO-40-SECOND-CUT.md` for the scene outline tied to actual event labels. No code from NMF, Half-Life, Wallet, Home Guard or Reproducer Commons is imported, and their previously published numbers are not recycled.
