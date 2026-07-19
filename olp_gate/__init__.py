"""OpenLine Receipt Gate v0.5.0rc2.

Proof-to-policy gate for risky agent actions.
"""

__version__ = "0.5.0rc2"

from .gate import gate, ReceiptGate, GatePolicy, Decision
from .receipts import verify_chain, load_receipts
from .adapters import TrustStore, assess_source_bundle
from .evidence import issue_outcome_receipt
from .gateway import evaluate_request, verify_decision_receipt, verify_decision_log
from .policy import PolicySpec
from .session import SessionLedger
from .model_swap import (
    build_model_swap_proof,
    run_verified_model_swap,
    verify_model_swap_output,
)
from .verified_commit import (
    VerifiedCommitError,
    VerifiedCommitLedger,
    execution_action_from_authorization,
    issue_one_use_code,
    run_verified_commit_demo,
    verify_verified_commit_output,
)

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
    "build_model_swap_proof",
    "run_verified_model_swap",
    "verify_model_swap_output",
    "VerifiedCommitError",
    "VerifiedCommitLedger",
    "execution_action_from_authorization",
    "issue_one_use_code",
    "run_verified_commit_demo",
    "verify_verified_commit_output",
]
