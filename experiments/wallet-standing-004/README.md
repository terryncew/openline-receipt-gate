# WALLET-STANDING-004 — Live Transport Continuity

**Base:** `openline-receipt-gate@9278b6238bf4f04e56184135913f4a7859db66bf`  
**Protocol mutation:** `NONE`  
**Wallet policy authority:** `NONE`

WALLET-STANDING-003 proved freeze, succession, virgin-Gate checkpoint, and fork-quarantine behavior under a deterministic in-process delivery schedule. 004 removes that scheduler.

Three Gate processes have separate memory and separate SQLite databases. They receive signed events over TCP through a fourth, untrusted relay process. The relay may delay, duplicate, reorder, or drop events, but it has no key and no authority. No Gate reads another Gate's database or mutable state.

The boundary under test is:

> A Gate can only stop authority it has learned about; once it has durably learned it, old authority must stop immediately at that Gate.

## Durability

`learned` means the 003 state transition has completed a local SQLite transaction with `PRAGMA synchronous=FULL`. The Gate emits its ACK only after `commit()` returns. A deliberate crash-before-commit arm must produce no ACK and, after restart, revision zero; redelivery must then be admitted normally.

`t_old_authority_stops` is the Gate's first local timestamp after that durable commit returns. Signature verification alone is not admission.

## Clock model

Before a scenario starts, the emitter performs a seven-sample NTP-style calibration handshake with each Gate and retains the lowest-RTT sample. Calibration is measurement-only: its offset is never passed to `wallet003`.

Because the 003 event schemas are frozen exact shapes, 004 does **not** add a timestamp field to them. Instead it signs a transport measurement envelope over the unchanged inner artifact hash plus `emitted_ns`. The envelope explicitly has authority `NONE` and is stripped before 003 admission.
`emitted_ns` is encoded inside that signed envelope as canonical decimal text, not an OLP integer: Unix epoch nanoseconds exceed OLP's interoperable `2^53-1` integer ceiling. The Gate parses it only for post-admission measurement; the representation cannot affect wallet003 policy.

For each admitted event, 004 reports raw `tau`, offset-corrected `tau`, transport lag, admission/commit lag, and calibration uncertainty. Values within the uncertainty bound are labeled `<= clock resolution`. Dropped/starved events are `undefined/censored`, never zero.

## Six fixed adversarial schedules

1. `race_to_window` — maximize legitimate pre-admission exposure, then prove zero effects after the durable freeze ACK.
2. `split_brain_delivery` — drop the freeze while Gate B is partitioned, execute at the edge, reconnect, admit, then require blocking.
3. `successor_race` — let A and B accept different valid generation-2 successors, then cross-deliver and require terminal 004 quarantine.
4. `cold_start_starvation` — keep Gate C closed while lineage/checkpoint data is withheld; after both arrive, the successor may execute.
5. `duplicate_storm_replay` — deliver fifty duplicates after the first freeze and require no deadline/state extension.
6. `cross_epoch_reorder` — deliver generation 2→3 before 1→2, require rejection, then admit in causal order without regression.

An additional crash-before-commit preflight tests the durability definition directly.

## Run

From repository root:

```bash
python -m pip install -e .
python -m unittest discover -s experiments/wallet-standing-004/tests -v
python experiments/wallet-standing-004/scripts/verify_release.py
python experiments/wallet-standing-004/scripts/run_live.py
python experiments/wallet-standing-004/scripts/verify_live.py
```

`run_live.py` writes `experiments/wallet-standing-004/live_result.json`. That file is runtime evidence and is intentionally excluded from the frozen release manifest because real transport timing is nondeterministic.

## Verdict

A passing run earns:

`LIVE_TRANSPORT_CONTINUITY_ENFORCED_WITH_MEASURED_PROPAGATION_LAG`

Any old-root effect after the relevant durable local admission, any virgin-Gate effect before lineage plus a fresh checkpoint, any replay/reorder standing regression, or any crash-before-commit resurrection fails the experiment.
