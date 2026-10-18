# Receiver evaluation — bounded acceptance record

**Scope:** public developer example only. The source is the frozen implementation in PR #121, copied without code changes. This record does not claim an independent organization's installation or integration.

**Internal result:** Both the OpenLine native-authority mode and correctly configured EdDSA JWT mode passed the same 16 adversarial HTTP scenarios (32 total), with independently verified signed decision evidence and protected local SQLite rows. The matched results were **PARITY**.

**Independent technical reproduction (October 18, 2026):** A clean-environment operator reported passing the PR #121 demo and 32/32 tests, with 5.24 seconds of automated setup and 11.95 seconds of checks in that environment. These durations omit an unfamiliar developer's real integration and troubleshooting effort. See original [PR #121 discussion](https://github.com/terryncew/openline-receipt-gate/pull/121) and its archived [source and evidence](https://github.com/terryncew/openline-receipt-gate/tree/study/independent-receiver-kit-001/examples/independent_receiver_kit/evidence).

**Negative findings:** Existing Wallet exports cannot be handed directly to this kit; native owner authorization is a different shape. A privileged SQLite writer can bypass the HTTP gate; the separately signed history can reveal inconsistency after the fact. Neither mode proves control over effects outside the database. Public test keys, a local fixed action, loopback transport, simulated worker labels and a single-receiver local state bound all claims. No security uniqueness, speed or integration-cost advantage over JWT is established.

**Next externally evaluated question:** Can an unfamiliar developer integrate a consequential *synthetic* action in reasonable time, verify decisions independently, and prefer OpenLine over an equivalently equipped conventional stack? Record exact steps, time, help required, custom code, verification work, failure modes and candid preference.

**Restrictions:** no real payments, privileged host experiments, deployment, production credentials, external contact or release authorized by this merge. Any outside evaluation or production integration requires a separate decision.
