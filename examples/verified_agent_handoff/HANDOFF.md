# HANDOFF — OPENLINE-ADOPTION-001 (2026-10-20 UTC)

**Authority:** owner-approved task-scoped **$0 engineering only**. No merges, Wallet/Lite/Half-Life/Airlock/NMF modifications, protected-main changes, model/API inference, downloads of models, production credentials/effects, deployment, public release or external outreach. All edits are on `feature/adoption-001-native-wallet-handoff-20261019` based on Receipt Gate main `76f72ccccce79622f40163763cf614bd1d7ff776`, proposed as a Draft PR. Read Receipt Gate's README/independent Kit README, Wallet source/PLATFORM-EXIT-LIVE-001/APPROVED-JOB-LIVE-001, Lite MODEL_HANDOFF and the frozen NMF Draft PR #24 reference boundary before modifying any source. Public Wallet pinned source `f309aac8aecae36c4f354c7455281af6dbce486a` (official Wallet verifier).

## What is actually built

1. **Native signed Wallet admission** added under the existing independent kit as `native_wallet.py`. It accepts unchanged `openline.wallet.receiver_bundle.v1` bytes/objects, verifies using the officially pinned Wallet `verify_bundle` and receiver-pinned owner root, cert/event chain, full-history monotonic frontier and <60s freshness, then checks current Wallet scopes against a separate worker-signed exact `receiver-kit-call/v1` for local document effect. Strict signature, worker possession, policy/action/record binding, durable one-use nonce, persistent SQLite effect and signed receiver decision. The existing kit's `Receiver(mode="openline"|"conventional")`, its source formats, its strong EdDSA JWT and its 16/16 matched cases remain unchanged. New `verify_native_wallet.py` independently verifies signed decision rows and reconstructs effects with the original pinned trust root. No format-conversion step, no altered Wallet canonical schema, no arbitrary shell interception.
2. **Installable command** `openline handoff prepare` / `openline handoff continue --agent codex` added via `olp_gate.handoff.adoption` and a new console script. Trusted local receiver runs approved `python -m unittest` checks on a clean exact Git checkpoint, records failures, signed file hashes/requirements/notes and current owner-managed revocation standing. Successor packet only issued after signature, exact HEAD/files and standing checks; it never silently upgrades an agent's prose into independently verified truth. Control/key directory must be outside model-writable repository. **This is not actual Claude/Codex invocation, no provider memory transfer and no production permission revocation over unrestricted Codex shell/filesystem.**
3. **Reproducible $0 quickstart:** `python3 -m examples.verified_agent_handoff.quickstart` makes a disposable synthetic repository; a scripted Claude-predecessor has ordinary PASS/no-mutation FAIL, the controller signs a checkpoint, a scripted Codex-successor receives no Claude chat/credentials, changes only the target file and produces a Git descendant passing both checks. An equally diligent conventional notes+Git+same-tests baseline succeeds as well. It is **PARITY on synthetic continuation**, not an earned reduction in time or error.
4. New tests `examples/independent_receiver_kit/test_native_wallet.py` (9) plus `tests/test_adoption_handoff.py` (10), matched legacy kit `test_receiver.py` (32) and local HTTP trust/SQLite verification. The clean source suite was executed by GitHub Actions [run 39358431504](https://github.com/terryncew/openline-receipt-gate/actions/runs/39358431504) at code commit `e023c4fc1d5b74155c2aa7f2b410677acada330b`: **51/51 tests, success** and actual one-command script. The six triggered repository workflows at that code SHA also completed success. No paid API/model calls.
5. Fact ledger: `ADOPTION-001-RESULTS.json`; instructions `README.md` (here) and `../independent_receiver_kit/NATIVE_WALLET.md`; root README and original kit README only **clarify** distinct native-Wallet support versus pre-existing kit format.

## Evidence and honesty

- Scripted elapsed **0.186 seconds** after environment setup is *not* clean outside-install time; conventional post-successor checks **41 ms** are differently scoped and **not a comparative latency win**.
- The 10-minute unassisted clean-developer setup/continuation target remains **UNTESTED**. Real provider continuation and reduced repeated work also unmeasured.
- Signatures prove byte attribution to a trusted local key; they don't make notes true or show that tests prove every code property. Original pre-switch live proofs remain frozen elsewhere; this new quickstart does **not** reproduce those provider runs.
- Receiver Kit protects **only the local SQLite document intake** that routes through its HTTP guard. The handoff CLI protects only emission of a successor packet. Neither constrains a Codex CLI's unrestricted filesystem, terminal, network, or arbitrary tool calls. Operators/root and private local control dirs are trusted. Privileged direct DB writes and revoked authority withheld from receiver remain serious limits.
- Strong conventional JWT with receiver-owned policy and evidence did as well as the original OLP Kit. Competent Git/notes/unittest/manual permissions also succeeded this scripted baseline. There is **no demonstrated comparative commercial superiority, onboarding win, or independent adoption**.

## How to reproduce and next owner gate

See `README.md` and `../independent_receiver_kit/NATIVE_WALLET.md`. Run from a clean checkout/venv with pinned Wallet library:
```sh
python3 -m pip install -e . -r examples/independent_receiver_kit/requirements.txt
python3 -m pip install 'git+https://github.com/terryncew/openline-wallet.git@f309aac8aecae36c4f354c7455281af6dbce486a'
python3 -m unittest examples.independent_receiver_kit.test_native_wallet -v
python3 -m unittest examples.independent_receiver_kit.test_receiver -v
python3 -m unittest discover -s tests -p 'test_adoption_handoff.py' -v
python3 -m examples.verified_agent_handoff.quickstart
```
Do not install inside real production system or invoke unknown owner-supplied unittest modules without sandboxing. The executable CLI and tests run as the invoking user.

**Engineering verdict: PASS within its $0 local scope. Adoption/commercial verdict: NOT YET PROVEN.** Next permitted step is independent fresh developer testing in a disposable checkout and a fair end-to-end baseline timing/errors study, with approval before any real-provider or consequential receiver action. No automatic merge/release, paid APIs, external contact, deployment or additional protected repo changes.

**PR/head:** final SHA, Draft PR number and latest full verification should be read back from GitHub after writing this file rather than assumed. Any follow-up review must check whether further code changed and repeat CI if necessary.
