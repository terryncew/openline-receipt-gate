# OPENLINE-ADOPTION-001 — verified agent handoff (local prototype)

**Promise to evaluate:** “Switch AI workers without losing your approved work, permissions, or verified progress.” This is a **$0 scripted developer proof**, not a hosted agent switcher or revocation sandbox.

## Clean install and first handoff

Python 3.11+ and Git. From the Receipt Gate feature branch `feature/adoption-001-native-wallet-handoff-20261019`:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/openline handoff prepare --help
.venv/bin/openline handoff continue --help
.venv/bin/python -m examples.verified_agent_handoff.quickstart
```

The script creates a **disposable Git repository**, simulates an approved, partially completed Claude coding task, records exact approved requirements and Git file hashes, **actually runs both named unittest checks**, signs the handoff using a new local receiver key stored **outside the worker repo**, and produces a verified Codex continuation packet. The ordinary numeric check passes; the approved no-mutation check fails. A deterministic successor then reads the handoff, fixes that same checked-out repository, commits a descendant and passes both checks. There is **no Claude or Codex API call**, no transferred conversation or credentials, and no production action. The predecessor's statement that tests passed remains *unverified text* beside the real failed test result.

Manual two-command shape (owner-protected control directory separate from project):

```sh
openline handoff prepare --repo ./my-safe-repo --approval ./owner-approved.json --control /safe/control/new-run
openline handoff continue --repo ./my-safe-repo --control /safe/control/new-run --agent codex
```

Prepare requires a **clean, committed Git checkout** and a JSON approval file with schema `openline.approved_job.v1`, `task_id`, `requirements`, `tests`, `unfinished`, and `notes`. Each test is a named argv array restricted to `python3 -m unittest` and arguments. It captures actual exit codes and output hashes and records failures without turning them into passes. The receiver controller signs the packet; the successor verifies exact Git HEAD, tracked file hashes, trust key, signature and revocation standing, then writes `continuation-codex.json` to the trusted control directory. This **does not automatically launch Codex**. No agent-created prose becomes a checked fact.

**Trust and authority limits:** The control directory/private key, approval and revocation standing are trusted local-operator inputs and **must not be writable by a worker**. This prototype does not establish independent owner identity, secure same-UID files, OS sandboxing, protected shell commands, distributed revocation delivery or authorized production effects. A Codex process with unrestricted shell access can bypass this wrapper; the program does not intercept such actions. The protected operation here is only **issuance of a verified continuation packet**, blocked if trusted permission is revoked or the checkpoint differs. A signed packet verifies those bytes and local test execution; it does not establish code correctness or prove every English requirement.

**Conventional baseline:** `CLAUDE.md` or equivalent notes + Git diff/status/commit history + the exact same tests and manually checked permissions can correctly continue this example. The scripted benchmark runs that diligent baseline and reports parity on the final correct continuation; no time/security superiority claim is earned. OpenLine adds a signed, machine-checked binding of the checkpoint and observed tests and an explicit failure-closed continuation interface, at the cost of controller/key/approval setup. A clean outsider ten-minute installation with no guidance is a **target not yet measured**. A developer familiar with Git may reasonably prefer conventional checks.

### Verify and audit

```sh
python3 -m unittest discover -s tests -p 'test_adoption_handoff.py' -v
python3 -m examples.verified_agent_handoff.quickstart
```

Tampering, missing receipt, uncommitted changes, new Git commit, revoked standing, forged signers, and false test claims are separate offline test cases. The CLI runs Python tests from the selected repository as the invoking user; this is not an untrusted-code sandbox. Use synthetic/disposable repositories only for this study.

Authority compatibility is a **separate** native-Wallet receiver example at `examples/independent_receiver_kit/native_wallet.py`; Wallet v0.1 is not claimed to authorize arbitrary Codex shell effects. No Half-Life compression was added: simple exact file hashes and a bounded signed checkpoint are sufficient for this first evaluation.
