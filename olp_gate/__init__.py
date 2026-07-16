"""OpenLine Receipt Gate v0.3.0.

Proof-to-policy gate for risky agent actions.
"""

__version__ = "0.3.0"

from .gate import gate, ReceiptGate, GatePolicy, Decision
from .receipts import verify_chain, load_receipts
from .adapters import TrustStore, assess_source_bundle
from .evidence import issue_outcome_receipt
from .gateway import evaluate_request, verify_decision_receipt, verify_decision_log
from .policy import PolicySpec
from .session import SessionLedger

__all__ = [
    "Decision",
    "GatePolicy",
    "PolicySpec",
    "ReceiptGate",
    "SessionLedger",
    "TrustStore",
    "assess_source_bundle",
    "evaluate_request",
    "gate",
    "issue_outcome_receipt",
    "load_receipts",
    "verify_chain",
    "verify_decision_log",
    "verify_decision_receipt",
]
