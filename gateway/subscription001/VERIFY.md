# Independent verification

You don't have to trust this repo's server code to check the demo's
central claim. The refusal receipt is signed with the receiver's
Ed25519 key; verification needs only the public key and the receipt.

## 1. Reproduce the demo

```bash
git clone https://github.com/terryncew/openline-receipt-gate
cd openline-receipt-gate
git checkout experiment/gateway-subscription-001
cd gateway
pip install -r requirements.txt
# Envoy 1.39.3 binary at $ENVOY_BIN, or use the Docker path below
./subscription001/run_demo.sh
```

Expect: every step prints PASS, exit code 0. Evidence lands in
`subscription001/run/evidence/<timestamp>/`.

Docker path (same code, containerized):

```bash
cd gateway/compose
AUTH_MODE=openline docker compose --profile openline up --build -d
# provision + drive per docs/QUICKSTART.md, or run the CI workflow
# .github/workflows/gateway-subscription-001-docker.yml
```

## 2. Verify the refusal receipt yourself

The demo writes `refusal_receipt.json` and `receiver.pubkey` into the
evidence directory. Check the signature without any gateway code:

```bash
cd subscription001
python3 verify_receipt_standalone.py \
  "$(cat run/evidence/<timestamp>/receiver.pubkey)" \
  run/evidence/<timestamp>/refusal_receipt.json
# expect: VALID: receipt gw-... decision=deny ...
```

What VALID means: the receipt's `receiver_sig` is a genuine Ed25519
signature by the holder of the receiver key over the canonical receipt
body, which records `decision: deny`, the `agent_revoked` reason, the
agent id, and the timestamp. What it does not mean: it proves the
receiver *decided* to refuse, not that any downstream system obeyed.

## 3. Verify the ledger effects

`transcript.json` records every balance assertion. Or query the demo
DB directly (sqlite3):

```bash
sqlite3 subscription001/run/state/demo.db \
  "SELECT acct, cents FROM balances;"
# treasury reflects exactly the authorized charges; vendor (the
# merchant's simulated settlement account) the same total.
sqlite3 subscription001/run/state/demo.db \
  "SELECT effect_id, body FROM effects;"
```

Replay any step: the transcript records the exact HTTP status codes
(200/403/409) per attempt.

## 4. Verify all receipts

```bash
cd gateway
GATEWAY_CONFIG=$PWD/subscription001/run/config \
GATEWAY_DB=$PWD/subscription001/run/state/demo.db \
python3 gateway_admin.py verify-receipts
# expect: receipts: N valid, 0 invalid
```

## 5. Challenge it

Found a bypass — a path where the merchant alters permissions, changes
trusted keys, or gets an unauthorized charge executed? That is the
point of the kit. The demo asserts these fail; if you find one that
doesn't, open an issue with reproduction steps.
