# sentry_live_demo.py

Deterministic demo of the SENTRY-LIVE-001 frozen live-guardian result.
Reads only `proofs/sentry-live-001/RESULT.json`. Makes no model calls,
no network calls, no randomness.

Run:

    python proofs/sentry-live-001/demo/sentry_live_demo.py
    python proofs/sentry-live-001/demo/sentry_live_demo.py --json

The demo refuses to present (exit 1) unless the frozen terminal
classification is the full PASS result, and it re-derives every final
decision from the frozen static + guardian decisions under the frozen
composition law before narrating. What it shows is checked, not told.

Tells the story in three moments:

1. The watcher helps (guardian HOLD -> QUARANTINE on an action the
   static owner rule would permit).
2. The watcher is fooled (guardian FINE on misleading context ->
   graceful fallback to the static COMMIT; the semantic danger was
   NOT blocked).
3. The watcher cannot erase the owner's rule (static DENY holds
   regardless of guardian output).
