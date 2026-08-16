# Pinned x402 Python MCP consequence-order comparison

## Status

`REPRODUCED_ON_PINNED_UPSTREAM`

This is a behavioral comparison against official x402 source, not a synthetic
attack matrix and not a claim about x402 as a whole.

## Question

At the pinned upstream commit, can the official asynchronous Python MCP payment
wrapper execute a tool side effect after payment verification but before
settlement, then return an error when settlement fails? If so, does Receipt
Gate's transaction airlock withhold the protected resource effect under the
same failure while still releasing it after a confirmed settlement?

## Frozen upstream surface

The repository, commit, source path, and source SHA-256 are recorded in
`SOURCE.json`. The runner refuses any other commit or source bytes.

## Three observations

1. **Native failure:** verification succeeds; the wrapped tool appends a line
   to a durable effect file; settlement raises; the official wrapper returns an
   error. A passing reproduction requires one durable tool effect despite the
   returned settlement error.
2. **Airlock failure:** fresh receiver appraisal succeeds; settlement raises;
   the protected release callback must not run and no release file may exist.
3. **Airlock legitimate control:** settlement returns a transaction hash and a
   matching confirmation; the protected release callback must run exactly once.

The runner also executes a native success control to show that the upstream
harness can complete the ordinary path.

## Pass rule

The comparison passes only if all of these are true:

- the exact upstream commit and source hash match the pin;
- static source inspection places the tool-handler call before the settlement
  call;
- the native settlement-failure run returns an error **and** leaves exactly one
  durable tool effect;
- the airlock settlement-failure run attempts settlement but leaves zero
  protected-release effects;
- both legitimate controls complete and produce exactly one effect;
- the standard-library independent verifier reproduces the source-order check,
  checks the recorded observations, and verifies the effect-file bytes.

## Falsifiers

This result is falsified for the pinned surface if the official wrapper no
longer executes the handler before settlement, the failed native run leaves no
effect, the airlock releases on settlement failure, or a legitimate airlock
transaction cannot release once.

## What it earns

It earns one narrow statement: **for the pinned official Python MCP wrapper,
an effectful handler can run before a settlement failure is known; the disclosed
Receipt Gate composition moves the protected resource effect behind matching
settlement confirmation.**

It does not prove production safety, a live-chain exploit, loss of funds,
correctness of external state providers, or a defect in every x402
implementation. Applications whose tool handler is read-only or reversible may
accept the upstream ordering. TypeScript and later Python implementations must
be assessed separately.

## Reproduce

```bash
git clone https://github.com/x402-foundation/x402.git /tmp/x402-upstream
git -C /tmp/x402-upstream checkout 167a828e8319aa7b403f4f4312489e9cffadff10

python benchmarks/x402_upstream_consequence/run_comparison.py \
  --upstream-root /tmp/x402-upstream
python scripts/verify_x402_upstream_consequence.py \
  --upstream-root /tmp/x402-upstream
```

