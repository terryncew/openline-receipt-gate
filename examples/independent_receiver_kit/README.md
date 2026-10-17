# Independent receiver kit

An offline, receiver-owned HTTP API accepts an external owner's authorization
and a worker's signed exact document-intake request. Both OpenLine and conventional
EdDSA JWT modes retain their own local history, policy, replay state and signed
decisions. No provider service or OpenLine-hosted authority is contacted.

**Bounded result: PARITY.** See [REPORT.md](REPORT.md) for actual timings, tests,
Wallet compatibility gap, APS overlap, trust assumptions and limits. This is an
internal reproducibility experiment, not an independent organization adoption test.

## Fresh checkout and install

From a fresh clone, select `study/independent-receiver-kit-001`, then from repo root:

```sh
python3 -m venv /tmp/receiver-kit-env
/tmp/receiver-kit-env/bin/python -m pip install --no-cache-dir -e . -r examples/independent_receiver_kit/requirements.txt
/tmp/receiver-kit-env/bin/python -m examples.independent_receiver_kit.demo --output /tmp/receiver-kit-demo
/tmp/receiver-kit-env/bin/python -m unittest examples.independent_receiver_kit.test_receiver -v
```

Use fresh output paths; evidence is never silently overwritten. The demo starts
real loopback-only receiving API subprocesses, sends owner/worker fixtures over
HTTP, restarts receivers between phases, and verifies both saved databases in
separate processes. Expected per mode: two documents, three owner-head records;
`ACCEPT, ALLOW, ACCEPT, DENY, ACCEPT, ALLOW, DENY`. Provider A/B labels are simulated,
not authenticated commercial model hosts. Keys and fixed clock are public test
apparatus. The receiver process is given only its outcome key and public config;
it does not receive issuer/worker private-key files.

Verify evidence separately, using independently trusted **public** receiver config:

```sh
/tmp/receiver-kit-env/bin/python -m examples.independent_receiver_kit.verify \
  --state /tmp/receiver-kit-demo/openline/state.sqlite3 \
  --config /tmp/receiver-kit-demo/openline/config.json --mode openline
```

For the conventional mode, substitute `conventional` in both paths and `--mode`.
A copied database plus public config can be verified without private keys or live
owner/provider service. Trust in those public pins must come from outside the DB.
The verifier reconstructs successful authorization/history and compares actual
protected rows. Signed denial reasons remain receiver testimony.

The seven-scenario demo is the smallest runnable integration. For standalone API
startup, it prepares `config.json` and public-fixture `receiver-test-key.txt`:

```sh
/tmp/receiver-kit-env/bin/python -m examples.independent_receiver_kit.receiver \
  --state /tmp/receiver-kit-demo/openline/state.sqlite3 \
  --config /tmp/receiver-kit-demo/openline/config.json \
  --key /tmp/receiver-kit-demo/openline/receiver-test-key.txt --mode openline \
  --fixture-clock 1792260020
```

It prints its loopback port. Only `POST /authority` (external signed owner record)
and `POST /submit` (`{"proof": <worker-signed exact request>}`) are supported.
There is no HTTP policy-admin or raw-write route. Omit `--fixture-clock` to use
system time; the recorded old fixtures then expire as they should. This example
is not a production service or a recommended key-management interface.

Receiver policy permits only a fixed local `send`/document-intake operation, with
zero money, no disclosures/delegation and a 128-character document limit. OpenLine
reuses its existing native owner authorization and mandate assessments. The worker
call envelope and signed decision are local example glue, not a new standardized
OpenLine protocol. JWT has the same application bindings and proof of possession.

Revocation takes effect after receiver admission. A signed head is fresh for
**less than 60 seconds from its signed issue time**, also bounded by owner and
mandate expiry. Duplicate delivery never renews freshness. Missing or stale
history fails closed. Withheld revocation can remain unknown until that window
closes; offline operation cannot discover an undelivered newer head.

The SQLite transaction binds the local head/policy check, nonce consumption,
fixed document insert and signed decision. No atomicity across external effects
is claimed. Authorized local administrators/database writers can bypass this HTTP
guard; the negative test records that effect and the verifier rejects it.

Clean-source/venv measurement, on an existing host (not a fresh OS or external user):

```sh
python3 -m examples.independent_receiver_kit.clean_install --output /tmp/receiver-kit-clean-run
```

The script exports committed HEAD, creates a fresh venv without inherited packages,
installs without pip's download cache, runs the demo and tests, and records exact
commands, raw logs and stage times. It refuses an existing output directory.
