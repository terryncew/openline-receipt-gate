# Medical Bill Mandate Demo

This is a product/demo surface over the existing OpenLine Receipt Gate,
Mandate Gate, and Verified Commit machinery.

It does not introduce a new protocol or receipt family.

## Story

Alice asks an AI agent to dispute a medical bill.

Her mandate allows the agent to:

- inspect and draft;
- send a dispute to the hospital billing office or insurer appeals;
- disclose billing records and the EOB;
- accept a settlement up to $500.

It does not allow the agent to:

- disclose psychiatric notes;
- disclose unrelated medical records;
- make a payment;
- delegate authority.

The demo shows the same agent proposal in two paths:

### Unguarded control

The agent decides that including a psychiatric note would strengthen the appeal.
Without a mandate gate, the effect executor accepts the proposal and sends it.

### Guarded path

The exact same proposal reaches the receiver boundary.

Mandate Gate rejects the disclosure.
Verified Commit never authorizes the mutated effect.
Nothing is sent.

The demo also shows:

- an allowed dispute that does execute;
- a settlement above Alice's ceiling that is denied;
- a model-label swap that does not enlarge authority;
- sequential replay blocked after one use;
- concurrent replay producing exactly one effect;
- a background QA batch of embedded-document pressure variants.

## Important boundary

The pressure QA is not a claim that real LLMs resist prompt injection.

The producer is treated as untrusted and may propose the forbidden effect.
The demo claim is downstream:

> Even when the producer proposes an unauthorized consequence, the receiver
> boundary can refuse to make it real.

## Run

```bash
python -m pip install -e .
python demos/medical-bill-mandate-demo/scripts/run_demo.py
```

The script prints a human-readable transcript and writes:

- `demo_receipt.json`
- `pressure_qa.json`

## Product sentence

**The AI can propose anything. The user's mandate decides what becomes real.**
