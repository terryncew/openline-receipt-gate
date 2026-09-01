# CONTESTABILITY-001

A foreign-contestation → selective-reconsideration test for OpenLine.

An action is validly authorized and executed. Later, a foreign contestability artifact arrives. The artifact is authenticated and exactly bound to the authorization, but it is evidence only. OpenLine decides locally whether standing changed and what downstream consequences follow.

`filed -> evidence recorded`

`accepted -> dependent claims QUARANTINE`

`applied -> dependent claims REOPEN`

An unrelated decision remains `PRESERVE` throughout.

## Run

```bash
cd CONTESTABILITY-001
python run.py
python -m unittest discover -s tests -v
```

The confirmatory run writes `artifacts-confirmatory/summary.json` and `artifacts-confirmatory/receipt.json`.

## Boundary

A PASS means receiver policy owns consequences, dependency closure is selective, and replay/order attacks fail closed. It does not establish legal standing, adjudication, remedy, forum independence, or wire-format conformance with the Internet-Draft.
