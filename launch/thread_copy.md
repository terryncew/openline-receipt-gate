I built the smallest OpenLine primitive:

Receipt Gate.

Add one line around an agent action.
Get a receipt.

Missing proof?
Quarantine.

No chain?
No badge.

Malformed receipt file?
Invalid chain, no traceback.

Raw evidence?
Not stored by default.

Examples:
tool call with no evidence hash → quarantined
memory write without user intent → review required
eval score without grader receipt → no badge
clean tool call → committed with receipt

The agent cannot just say it did the thing.

It has to pass the gate.
