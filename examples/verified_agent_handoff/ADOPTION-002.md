# OPENLINE-ADOPTION-002 — Verified Successor Launch (local, $0)

**Status:** narrowly supported Linux root-owned, separate Unix UID scripted-process proof. **Not** a general Codex/Claude launcher, sandbox, production agent isolation, mid-execution cancellation, or proof of arbitrary downstream effects.

## Why ADOPTION-001 alone was unsafe

With a worker under the **same OS user** as the controller, `standing.json` was an unsigned, writable file. A revoked state could be rewritten to its initial `{"revoked":false,"sequence":0}` and `openline handoff continue --agent codex` would issue its original informational packet. `tests/test_adoption_002_launch.py::LegacyStandingAttack` reproduces that failure unchanged. The old packet is **not a permission to launch a process**. ADOPTION-002 marks the legacy packet `authority_verified:false`, `permission_standing:UNAUTHENTICATED_LEGACY_SHARED_UID`, and `launch_authority:false`; its insecure standing file is never accepted by the protected launch path.

## Supported execution model and owner root

Only Linux, root-owned controller state, owner/bootstrap command executed as root, a distinct non-root worker UID with no root group, a disposable preapproved synthetic Git repo, and a separately pinned root public key. The *worker does not run any controller commands as root*, has no `sudo` grant, and does not share its UID with the controller. Control directory is root:0700; keys, authority log, frontier and receipt entries are root:0600. A separate owner-pinned public key file must also be root-owned and not worker-writable. An OS/admin adversary with root, uncontrolled `sudo`, raw block-disk access, backup rollback of **both** root-owned ledger and frontier, or ability to change privileged system time remains outside scope. If root separation is absent, `launch` refuses; it does **not** fall back to same-UID permission bits or an unsigned standing file.

The controller reads one owner-approved JSON job, binds exact tracked file hashes and Git HEAD, signs the checkpoint, and creates an owner-signed monotonic `ACTIVE` event with a separately root-owned frontier. Revocation appends an owner-signed `REVOKED` event, advances the frontier and is irreversible in this local v1. The latest signed record, exact predecessor chain and frontier must match before launch. Worker-initiated rollback, replacement of public roots/keys, stale signed checkpoint, forged receipt and revocation are refused. These controls depend on Linux enforcing root/UID separation; signed data alone cannot guarantee anti-rollback if the worker can replace **all** durable state.

## Actual launch

Install from this Draft PR branch into a local virtual environment. **Only use synthetic/disposable Git repositories; do not run root controllers against untrusted projects** (even repository metadata can be hostile). For example, set a root-owned empty parent such as `/var/tmp/owner-trusted` (0700), ensure Git repository and approval file are owner-controlled, and select a dedicated unprivileged UID without sudo:

```sh
sudo openline handoff owner-init \
  --repo /disposable/approved-project --approval /owner/approved-job.json \
  --control /var/tmp/owner-trusted/controller \
  --pin /var/tmp/owner-trusted/pinned-owner-root.json --worker-uid 65534

sudo openline handoff launch \
  --repo /disposable/approved-project \
  --control /var/tmp/owner-trusted/controller \
  --pin /var/tmp/owner-trusted/pinned-owner-root.json --worker-uid 65534

sudo openline handoff owner-revoke \
  --control /var/tmp/owner-trusted/controller \
  --pin /var/tmp/owner-trusted/pinned-owner-root.json
```

You can also call `python3 -m olp_gate.handoff.isolated_launch [owner-init|launch|owner-revoke]` as root. No actual Claude, Codex or external model call is made.

The controller takes an exclusive lock, verifies the exact signed authority and checkpoint, copies each tracked file byte-for-byte into a **new root-owned read-only staging tree**, independently rechecks Git HEAD and all source hashes, rechecks signed authority under the same lock, and launches a **fixed scripted Python process** with `setgroups([])`, distinct `setgid` and `setuid`, empty stdin, minimal environment, and a worker-owned temporary output folder. The worker receives only an immutable JSON continuation packet and checked file snapshot; it **tries and fails** to write the root-owned authority ledger. There is no arbitrary user-supplied process/command, provider authentication, filesystem write access outside the disposable worker sandbox, or production effect demonstration. Root-signed receipts record the exact versioned checkpoint, worker UID, observed child exit, and denial reasons; an independent verifier given the **externally pinned** public key can verify their bytes using `verify_receipt`. A signed receipt still represents the controller's testimony, not an objective proof that downstream behavior was complete.

A mutation in the original repository after snapshot but before child creation is rechecked and refused. The launched process consumes the immutable snapshot, never a time-of-check-sensitive path into the original repository. Original repo commits made **after** launch cannot change already launched code; such changes do not retroactively cancel a child. Mid-process revocation, arbitrary network effects and later shell actions are **not** controlled by this proof.

## Reproduction and control comparison

```sh
python3 -m pip install -e .
python3 -m unittest tests.test_adoption_handoff -v
sudo env PATH="$PATH" PYTHONPATH="$PWD" python3 -m unittest tests.test_adoption_002_launch -v
openline handoff launch --help
```

The suite first proves the **historical same-UID rollback vulnerability**, then proves the supported root-owned launcher denies unauthorised process creation, old signed checkpoint reuse, replaced trust roots, malformed history, ledger rollback, revoked state, and source changes between verify and spawn. It starts the real unprivileged worker for current authority and checks the worker's attempted direct control modification was denied. An unrelated independently authorized task remains launchable. All effects are disposable local files.

**Conventional baseline:** run `openline handoff launch ... --baseline` for the same root/UID isolation, trusted signing, owner revocation, source pinning, lock, checkpoint stage and one identical scripted worker. This evaluates a properly configured conventional owner-controlled launcher, not a weak shell script. It uses the **same enforcement machinery** (differing only the report's mode label), so equal security is expected *by construction*: it is an implementation parity check, not evidence of an OpenLine commercial advantage. Production installation labor, independent developer adoption and alternative codebases are unmeasured. Standard POSIX isolation plus appropriately signed state is enough to pass this experiment.

**Consequence boundary:** only local process launch is authorized. The fixed scripted worker receives no general Codex shell access. Any future real worker, Docker/container executor, network call, filesystem mount, credential, or provider API requires a new separate threat model and authorization. On unsupported OS identity separation, verdict **BLOCKED**.

Run 001/002/003, PRs #22–#24, Wallet/Lite/Half-Life/Airlock and prior adopted receiver-kit proofs remain unmodified. No paid APIs, releases, merges, deployments, external contact or public claims.
