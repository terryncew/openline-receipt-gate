# Protect a consequential function

`olp-gate protect` turns application rules into a small OpenLine starter without requiring a developer to learn the internal authorization vocabulary first.

The first template is intentionally narrow:

```bash
olp-gate protect refund
```

It asks who the agent is acting for, how much it may refund under an automatic rule, the absolute refund ceiling, how fresh approval must be, how long a cleared action may wait before rechecking, and when the policy expires. OpenLine does not choose those values for you.

The default output is `.openline/refund/`:

```text
answers.json
refund_policy.json
refund_guard.py
README.md
test_refund_policy.py
```

The generated high-value approval hook returns `None` until you connect a trusted approval source. That is deliberate: missing approval remains blocked rather than being filled in by model reasoning.

For scripts and CI, provide every consequential value explicitly:

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

`--non-interactive` fails if any of those values are missing. Existing generated files are preserved unless `--force` is supplied.

## What the starter is doing

The developer owns the rules. The generated policy makes them machine-readable, and the generated guard attaches them to one exact function boundary. The agent may propose a refund, but it does not get to supply the principal, raise the limits, extend the approval window, or substitute its own explanation when trusted approval is absent.

This command is authoring help, not a policy oracle. Future templates should follow the same rule: ask ordinary questions, record the answers, generate conservative wiring, and never let the generator manufacture authority.
