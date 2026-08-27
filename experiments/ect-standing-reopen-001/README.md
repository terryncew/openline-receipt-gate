# Evidence-Carrying Termination Standing/Reopen 001 (ECT-001)

**External status:** `AUTHOR_VERIFIER_UNAVAILABLE`  
**Policy authority:** `NONE`  
**Runtime permission:** `NONE`

ECT-001 tests a narrow composition boundary between Jason Liu's Evidence-Carrying Termination (ECT) and OpenLine.

ECT owns the answer to: **was COMPLETE supported at t0?**  
OpenLine owns only the later answer: **does that already-admitted completion still have standing at t1?**

OpenLine never replays ECT, grades its claims, or substitutes its own certificate verifier.

## Pinned external source

- Jason Liu, *When May an Agent Stop? Evidence-Carrying Termination for Tool-Using LLMs*
- `arXiv:2608.23623v1`
- submitted 2026-08-22

The versioned paper is located and pinned. As of the frozen discovery on 2026-08-27, no public executable author verifier was located through the canonical paper record, exact-title/code/artifact web searches, or GitHub searches for the title, arXiv id, and distinctive ECT phrases.

That is a hard boundary. The external run therefore stops before t0 admission with:

`AUTHOR_VERIFIER_UNAVAILABLE`

and leaves t1 `UNASSESSED`.

## What is implemented

`ect001/standing.py` is deliberately a t1-only adapter. It accepts an opaque author-issued certificate digest plus its admitted dependency basis **only after** an external attestation says the author verifier passed. It then performs one operation:

```text
already author-verified t0 basis
              +
      later lost-standing set
              |
              v
     intersection non-empty?
          /          \
        yes          no
      REOPEN      NO_REOPEN
```

The unit tests use synthetic opaque attestations only to test this interface contract. They are not ECT certificates and are never reported as external evidence.

## Current external result

The current cold run is intentionally blocked rather than reconstructed:

- t0 certificate validity: `UNASSESSED`
- author verifier: `NOT_LOCATED_PUBLICLY`
- OpenLine t1 standing: `UNASSESSED / NOT_EXECUTED`
- ECT verifier recreated by OpenLine: `false`
- claim: `NO_ECT_STANDING_RESULT`

This is the falsifier doing its job. A cold integration that cannot preserve upstream authority does not get to call itself an integration.

## Run

From this directory:

```bash
python -m unittest discover -s tests -v
python scripts/run_cold_external.py
python scripts/verify_release.py
```

When an authentic author verifier artifact becomes publicly pin-able, the next admissible change is to add its exact immutable pin and invocation/output adapter. The local t1 logic does not need an ECT implementation.
