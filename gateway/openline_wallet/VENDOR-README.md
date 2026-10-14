# Vendored OpenLine Wallet authority contracts

**Source:** `github.com/terryncew/openline-wallet` @ `c46e82a324199050239540f1825a3b0c942e4053`
**Vendored:** 2026-10-11 (OPENLINE-RECEIVER-001 Priority 2)
**Files:** `__init__.py`, `wallet.py`, `receiver.py`, `crypto.py`,
`canonical.py`, `clock.py`, `errors.py`, `storage.py`
(dependency closure for `Wallet` + `ReferenceGate`; 20-file package
trimmed to the 8 files the gateway needs)

## Why vendored, not invented

OPENLINE-RECEIVER-001 Priority 2 requires the gateway to accept
portable Wallet authority. The mandate/bundle/presentation formats are
defined by the Wallet repo. This directory is a byte-copy of those
contracts — the gateway does NOT define a parallel authority format.
If the Wallet changes these files, re-vendor and re-run the P2 demo.

## What the gateway uses

- `Wallet.grant` / `Wallet.revoke` / `Wallet.export_bundle` (owner side,
  used by the P2 demo to issue portable mandates)
- `ReferenceGate.pin_principal` / `admit_bundle` / `issue_challenge` /
  `evaluate` (receiver side, used by `gateway/wallet_bridge.py`)

## What the gateway does NOT use

The Wallet's CLI, MCP bridge, capability installer, demo scripts, and
proofs are not vendored and not needed for receiver-side verification.
