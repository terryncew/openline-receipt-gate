# FIRE DRILL — 40-second demonstration cut (source-driven, not a staged terminal)

**Format:** self-contained browser playback in `fire-drill-40s.html`. A timed 8 × 5-second editorial storyboard generated from **the actual local HTTP decisions** of each fresh run. This is not a recorded model call, an MP4, or a recording of production incidents. It can be screen-recorded after independent verification, but neither source code nor script may claim live agents.

| Time | Frame | Evidence shown / strict scope |
|---|---|---|
| 0–5 | “Can you fire an AI agent—and actually stop it?” | Challenge question; no incident claims |
| 5–10 | “Agent A completes one approved action.” | Each receiver's saved `approved_a_work` decision + `job-before` SQLite row |
| 10–15 | “The owner withdraws permission.” | `owner_revokes_a` receipt for both strong modes; weak is **advisory-only** |
| 15–20 | “Old A tries new writes and a side route.” | Sum of **actual `documents_after - documents_before`** for four defined post-revocation old-A operations: teaching counterexample vs JWT vs OpenLine. No vendor logos, no fabricated losers |
| 20–25 | “An exact request is replayed.” | `exact_replay_before_revocation` and `a_exact_replay`; weak bearer reused for a *new* document is a different attack, clearly distinguished |
| 25–30 | “A successor completes the task.” | Accepted `job-successor` row and `unrelated-work` row at distinct receiver/authority slot. These are local document effects, not general software correctness |
| 30–35 | “What happens outside the gate?” | Each mode has a separately observed, **ungated SQLite insert**. OpenLine cannot intercept it. This is a legitimate negative result |
| 35–40 | “Verify the evidence yourself.” | MANIFEST.json hash and independent existing receiver-kit verifier; OpenLine and well-secured conventional JWT can both pass |

**Design:** restrained navy background, orange signal, one editorial thought per frame, no unexplained wireframes/space backgrounds, no fake console text. Pauses are enforced by client-side elapsed time; pressing Replay restarts. Data is injected by `render.py` from each completed experiment's decision journal. A video export would require separate real playback capture and may only be distributed after separately approved public launch.

**Honesty test:** should the source signatures or stored decisions fail independent verification, **do not** present the generated HTML as a verified Fire Drill. It is an illustrative replay of local observations, with limits printed within the content and documented beside the bundle.
