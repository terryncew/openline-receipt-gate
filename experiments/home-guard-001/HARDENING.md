# HOME-GUARD-001 post-freeze hardening (Draft PR #111)

Scope: offline prototype only. Frozen HOME-GUARD-001 criteria, eight original
tests, signed receipts, and evidence hashes remain byte-unchanged. No system
firewall is configured by this commit.

## Changes
- Simulator caller identity is bound to the established session. Previously
  a call identifying itself as TV with session identity thermostat could create
  a TV route using thermostat privileges. The session identity remains a fiat
  simulator assumption, not authenticated network identity.
- An *opt-in strict route* uses explicit SQLite persistent state and admitted
  mandates. Signed ALLOW is refused after durable revocation, and spent nonces
  survive receiver/device recreation. Atomic consume happens before the effect.
  A crash can lose an allowed action, not repeat it.
- Strict receiver mode requires a caller public-key value from an independent
  authenticated boundary, matched to mandate grantee. The prototype does
  not establish the transport authentication itself.
- Expiry comparisons normalize offset-aware ISO timestamps to UTC.
- Network receipts are signed once after their final verdict.

## Limitations
The frozen legacy demo retains its in-memory route so signed receipts remain
byte-identical. It is NOT production-safe. Strict mode is separately tested
and must be selected by an independently trusted receiver integration. No
application-code-only mode can guarantee an uncooperative TV cannot open
another socket. HOME-GUARD-002 tests that separately with Linux packet
forwarding/firewall rules in disposable virtual namespaces.

No real household network, devices, firmware, key custody or credential
rotation, power-loss durability, external authenticated identity, or remote
multi-host revocation has been proven.

Reproduce:
  python -m unittest discover -s experiments/home-guard-001/tests -v
  python -m unittest discover -s experiments/home-guard-001/hardening_tests -v
  python experiments/home-guard-001/home_guard/demo.py
Frozen receipts SHA-256:
  3bc49332c75315a305d84e2afcf55cde6acf546e6f265f5c6fb04e40e31e49aa
