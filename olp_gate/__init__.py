"""OpenLine Receipt Gate v0.1.1.

One-line receipt gate for risky agent actions.
"""

__version__ = "0.1.1"

from .gate import gate, ReceiptGate, GatePolicy, Decision
from .receipts import verify_chain, load_receipts
