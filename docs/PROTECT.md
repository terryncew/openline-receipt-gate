# Protect a consequential function

`olp-gate protect` turns application rules into small OpenLine starters without
requiring a developer to learn the internal authorization vocabulary first.

The command is organized around policy packs:

```bash
olp-gate protect refund
olp-gate protect send-message
```

A policy pack is not a new gate or a new execution mechanism. It is an authoring
adapter for a familiar consequential action. The developer answers ordinary
questions; the pack records those answers and generates conservative wiring for
the existing authorization path.

## Refund

The refund pack asks who the agent acts for, how much it may refund under an
automatic rule, the absolute ceiling, how fresh approval must be, how long a
cleared action may wait before rechecking, and when the policy expires.

The generated high-value approval hook returns `None` until a trusted approval
source is connected. Missing approval stays blocked.

```bash
olp-gate protect refund \
  --owner merchant-001 \
  --autonomous-limit 100.00 \
  --hard-limit 1000.00 \
  --approval-max-age 300 \
  --authorization-ttl 120 \
  --expires-at 2027-12-31T23:59:59Z \
  --non-interactive \
  --yes
```

## Send message

The messaging pack asks who the agent acts for, which recipients are listed,
whether every exact message needs approval or listed recipients may receive new
content autonomously, how fresh approval must be, how long a cleared send may
wait, and when the policy expires.

The safer mode is `exact-approval`:

```bash
olp-gate protect send-message \
  --owner principal-001 \
  --content-mode exact-approval \
  --approval-max-age 300 \
  --authorization-ttl 120 \
  --expires-at 2027-12-31T23:59:59Z \
  --non-interactive \
  --yes
```

To allow new content only to a fixed list:

```bash
olp-gate protect send-message \
  --owner principal-001 \
  --allowed-recipient alice@example.com \
  --allowed-recipient ops@example.com \
  --content-mode autonomous-for-listed \
  --approval-max-age 300 \
  --authorization-ttl 120 \
  --expires-at 2027-12-31T23:59:59Z \
  --non-interactive \
  --yes
```

The generated `message_approval_key(call)` hashes the exact recipient and
message body. A receiver-owned approval store should use that key. Change the
recipient or message and the key changes, so an old approval does not silently
cover the altered send.

`trusted_exact_message_approval()` returns `None` until the developer connects
a real approval source. Do not substitute model output or caller prose as
approval.

## Rules shared by every pack

`--non-interactive` fails if a consequential value is missing. Existing
generated files are preserved unless `--force` is supplied.

The developer owns the rules. OpenLine records and enforces them. A pack may
suggest conservative structure, but it may not manufacture the principal,
expand its own authority, or convert missing trusted evidence into permission.

Future payments, deployments, data exports and permission changes should fit
behind the same `olp-gate protect <action>` surface rather than becoming a
collection of new named gates.
