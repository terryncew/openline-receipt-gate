"""OpenLine Receipt Gate v0.6.0rc6.

Proof-to-policy gate for risky agent actions.
"""

__version__ = "0.6.0rc6"

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
from .authority_compiler import (
    AUTHORITY_COMPILER_SETTINGS_PROFILE,
    AuthorityCompiler,
    AuthorityCompilerError,
    validate_compiler_result,
)

from .handoff import (
    HandoffAdapterError,
    HandoffCheckError,
    inspect_handoff,
    load_history as load_handoff_history,
    restore_items as restore_handoff_items,
    write_handoff_outputs,
)
from .role_confusion import (
    ConsequenceGateError,
    appraise_consequence,
    consequence_action_hash,
    execute_appraised_consequence,
    run_case_matrix,
)
from .x402_airlock import (
    X402_AIRLOCK_PROFILE,
    X402_CONFIRMATION_PROFILE,
    X402_POLICY_PROFILE,
    X402_RELEASE_REQUEST_PROFILE,
    X402_RELEASE_RESULT_PROFILE,
    X402_SNAPSHOT_PROFILE,
    X402AirlockError,
    evaluate_x402_preflight,
    execute_x402_once,
    validate_x402_issue,
    verification_context_hash,
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
    "AUTHORITY_COMPILER_SETTINGS_PROFILE",
    "AuthorityCompiler",
    "AuthorityCompilerError",
    "validate_compiler_result",
    "HandoffAdapterError",
    "HandoffCheckError",
    "inspect_handoff",
    "load_handoff_history",
    "restore_handoff_items",
    "write_handoff_outputs",
    "ConsequenceGateError",
    "appraise_consequence",
    "consequence_action_hash",
    "execute_appraised_consequence",
    "run_case_matrix",
    "X402_AIRLOCK_PROFILE",
    "X402_CONFIRMATION_PROFILE",
    "X402_POLICY_PROFILE",
    "X402_RELEASE_REQUEST_PROFILE",
    "X402_RELEASE_RESULT_PROFILE",
    "X402_SNAPSHOT_PROFILE",
    "X402AirlockError",
    "evaluate_x402_preflight",
    "execute_x402_once",
    "validate_x402_issue",
    "verification_context_hash",
]
