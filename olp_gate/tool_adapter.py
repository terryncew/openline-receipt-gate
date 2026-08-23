"""Drop-in function guard backed by OpenLine Authority Compiler.

This module is deliberately thin. It does not invent another authorization
primitive. It adapts an ordinary Python function call into an AuthorityCompiler
proposal, then uses the existing Proof-to-Policy + Verified Commit path to
execute the exact call once.

Frameworks such as LangGraph can wrap the guarded callable normally. The guard
belongs immediately inside the framework's tool decorator so the model never
receives a bypass around the function boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
import base64
import inspect
import json
import os
from pathlib import Path
import secrets
from typing import Any, Callable, Mapping, MutableMapping, Sequence

from .authority_compiler import AuthorityCompiler, validate_compiler_result
from .authority_link import canonical_hash


POLICY_BUNDLE_SCHEMA = "openline.authorized_tool_policy.v1"
TOOL_ADAPTER_PROFILE = "openline.authorized_tool/v1"
_HEX = frozenset("0123456789abcdef")


class ToolAdapterError(ValueError):
    """Raised when a guarded tool is misconfigured."""


class AuthorizationBlocked(PermissionError):
    """Raised before a guarded function when authority is absent or stale."""

    def __init__(
        self,
        decision: str,
        reason_codes: Sequence[str],
        *,
        compilation: Mapping[str, Any] | None = None,
        decision_receipt: Mapping[str, Any] | None = None,
    ) -> None:
        self.decision = decision
        self.reason_codes = tuple(sorted(set(str(item) for item in reason_codes)))
        self.compilation = dict(compilation) if isinstance(compilation, Mapping) else None
        self.decision_receipt = (
            dict(decision_receipt) if isinstance(decision_receipt, Mapping) else None
        )
        detail = ",".join(self.reason_codes) if self.reason_codes else "authority_missing"
        super().__init__(f"openline:{decision}:{detail}")


@dataclass(frozen=True)
class ToolCallContext:
    tool: str
    target: str
    arguments: Mapping[str, Any]
    proposal_id: str
    producer_id: str
    producer_model: str
    objective: str


@dataclass(frozen=True)
class EvidenceAssertion:
    """Receiver-side evidence provider output.

    Returning ``None`` from a provider means the requirement is unavailable.
    Returning ``True`` or a mapping is shorthand for a fresh verified assertion.
    """

    payload: Mapping[str, Any]
    issuer_id: str | None = None
    expires_in_seconds: int | None = None
    revoked: bool = False
    verified: bool = True
    issued_at: datetime | None = None


@dataclass(frozen=True)
class AuthorizedValue:
    value: Any
    decision_receipt: Mapping[str, Any]
    compilation: Mapping[str, Any]
    execution: Mapping[str, Any]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ToolAdapterError("timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ToolAdapterError("timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise ToolAdapterError("timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in _HEX for char in value)
    )


def _json_copy(value: Any) -> Any:
    """Freeze the exact values that will be proposed and later executed."""
    def reject_float(item: Any, path: str = "$") -> None:
        if isinstance(item, float):
            raise ToolAdapterError(f"tool_argument_float_forbidden:{path}")
        if isinstance(item, list) or isinstance(item, tuple):
            for index, child in enumerate(item):
                reject_float(child, f"{path}[{index}]")
        elif isinstance(item, Mapping):
            for key, child in item.items():
                reject_float(child, f"{path}.{key}")
    reject_float(value)
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise ToolAdapterError("tool_arguments_must_be_json") from exc


def _load_bundle(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        bundle = _json_copy(dict(value))
    else:
        path = Path(value)
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ToolAdapterError(f"policy_bundle_unreadable:{path}") from exc
    if not isinstance(bundle, dict):
        raise ToolAdapterError("policy_bundle_invalid")
    if bundle.get("schema") != POLICY_BUNDLE_SCHEMA:
        raise ToolAdapterError("policy_bundle_schema_invalid")
    if set(bundle) != {"schema", "mandate", "permission_policy"}:
        raise ToolAdapterError("policy_bundle_shape_invalid")
    if not isinstance(bundle["mandate"], dict) or not isinstance(
        bundle["permission_policy"], dict
    ):
        raise ToolAdapterError("policy_bundle_sections_invalid")
    return bundle


def payment_semantics(
    amount_argument: str = "amount_cents",
    *,
    action_type: str = "authorize_payment",
) -> Callable[[ToolCallContext], Mapping[str, Any]]:
    """Convenience resolver for money-moving tools that use integer cents."""

    def resolve(call: ToolCallContext) -> Mapping[str, Any]:
        amount = call.arguments.get(amount_argument)
        if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
            raise ToolAdapterError(f"payment_amount_invalid:{amount_argument}")
        return {
            "action_type": action_type,
            "disclosures": [],
            "value_cents": amount,
            "delegatee": None,
        }

    return resolve


def _context_from_proposal(proposal: Mapping[str, Any]) -> ToolCallContext:
    return ToolCallContext(
        tool=str(proposal["tool"]),
        target=str(proposal["target"]),
        arguments=_json_copy(proposal["settings"]),
        proposal_id=str(proposal["proposal_id"]),
        producer_id=str(proposal["producer_id"]),
        producer_model=str(proposal["producer_model"]),
        objective=str(proposal["objective"]),
    )


def _normalize_provider_result(
    value: Any,
    *,
    default_issuer: str,
    max_age_seconds: int,
    now: datetime,
) -> EvidenceAssertion | None:
    if value is None or value is False:
        return None
    if isinstance(value, EvidenceAssertion):
        assertion = value
    elif value is True:
        assertion = EvidenceAssertion(payload={"verified": True})
    elif isinstance(value, Mapping):
        assertion = EvidenceAssertion(payload=_json_copy(dict(value)))
    else:
        raise ToolAdapterError("evidence_provider_result_invalid")
    issued = assertion.issued_at or now
    if issued.tzinfo is None:
        raise ToolAdapterError("evidence_issued_at_timezone_required")
    expires_in = assertion.expires_in_seconds
    if expires_in is None:
        expires_in = min(max_age_seconds, 60)
    if not isinstance(expires_in, int) or isinstance(expires_in, bool) or expires_in <= 0:
        raise ToolAdapterError("evidence_expiry_invalid")
    return EvidenceAssertion(
        payload=_json_copy(dict(assertion.payload)),
        issuer_id=assertion.issuer_id or default_issuer,
        expires_in_seconds=expires_in,
        revoked=assertion.revoked,
        verified=assertion.verified,
        issued_at=issued.astimezone(timezone.utc),
    )


class LocalAuthorityRuntime:
    """Small local receiver runtime for the reference adapter.

    Keys and replay state are receiver-owned files under ``runtime_dir``. This
    is intended for a local service/tool boundary and reference integration,
    not as a replacement for an organization's KMS or distributed signer.
    """

    def __init__(self, runtime_dir: str | Path = ".openline/runtime") -> None:
        self.root = Path(runtime_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.keys_dir = self.root / "keys"
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.compiler_log = self.root / "compiler_results.jsonl"
        self.decision_log = self.root / "decision_receipts.jsonl"
        self.session_path = self.root / "session_ledger.json"
        self.commit_ledger_path = self.root / "verified_commit_ledger.json"

    @staticmethod
    def _append_jsonl(path: Path, value: Mapping[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, ensure_ascii=True))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())

    def record_compilation(self, compilation: Mapping[str, Any]) -> None:
        self._append_jsonl(self.compiler_log, dict(compilation))

    def _key(self, name: str):
        # Lazy imports keep the plain decorator testable without the full
        # cryptographic runtime present in a shadow/minimal environment.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        path = self.keys_dir / f"{name}.key"
        if path.exists():
            raw = path.read_text(encoding="ascii").strip()
            try:
                key_bytes = bytes.fromhex(raw)
            except ValueError as exc:
                raise ToolAdapterError(f"runtime_key_invalid:{name}") from exc
            if len(key_bytes) != 32:
                raise ToolAdapterError(f"runtime_key_invalid:{name}")
            return Ed25519PrivateKey.from_private_bytes(key_bytes)
        key = Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError:
            return self._key(name)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            handle.write(raw + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return key

    @staticmethod
    def _u64(value: bytes) -> str:
        return "u" + base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def _source_receipt(
        self,
        *,
        key: Any,
        method: str,
        run_id: str,
        session_id: str,
        action_id: str,
        response_hash: str,
        now: datetime,
    ) -> dict[str, Any]:
        from .crypto import jcs_integer_canonical_json

        observed = _iso(now)
        body: dict[str, Any] = {
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://agentreceipts.ai/context/v2",
            ],
            "id": f"urn:receipt:{action_id}",
            "type": ["VerifiableCredential", "AgentReceipt"],
            "version": "0.5.0",
            "issuer": {
                "id": "did:openline:local-tool-adapter",
                "type": "AIAgent",
                "session_id": session_id,
            },
            "issuanceDate": observed,
            "credentialSubject": {
                "principal": {
                    "id": "did:openline:local-receiver",
                    "type": "HumanPrincipal",
                },
                "action": {
                    "id": action_id,
                    "type": "tool_call",
                    "risk_level": "high",
                    "timestamp": observed,
                },
                "outcome": {
                    "status": "success",
                    "reversible": False,
                    "response_hash": "sha256:" + response_hash,
                },
                "chain": {
                    "sequence": 1,
                    "previous_receipt_hash": None,
                    "chain_id": run_id,
                    "terminal": True,
                    "status": "complete",
                },
            },
        }
        signature = key.sign(jcs_integer_canonical_json(body))
        return {
            **body,
            "proof": {
                "type": "Ed25519Signature2020",
                "created": observed,
                "verificationMethod": method,
                "proofPurpose": "assertionMethod",
                "proofValue": self._u64(signature),
            },
        }

    @staticmethod
    def _source_hash(receipt: Mapping[str, Any]) -> str:
        from .crypto import jcs_integer_canonical_json, sha256_hex

        body = dict(receipt)
        body.pop("proof", None)
        return sha256_hex(jcs_integer_canonical_json(body))

    def execute(
        self,
        *,
        compiler: AuthorityCompiler,
        proposal: Mapping[str, Any],
        compilation: Mapping[str, Any],
        executor: Callable[[], Any],
        now: datetime,
    ) -> AuthorizedValue:
        from .adapters import TrustStore
        from .crypto import public_key_hex, sha256_hex
        from .evidence import issue_outcome_receipt
        from .gateway import evaluate_request
        from .policy import PolicySpec
        from .session import SessionLedger
        from .verified_commit import (
            VerifiedCommitLedger,
            issue_one_use_code,
            settings_hash,
        )

        checked = validate_compiler_result(compilation)
        if checked["decision"] != "COMMIT_ELIGIBLE":
            raise AuthorizationBlocked(
                checked["decision"], checked["reason_codes"], compilation=checked
            )
        source_key = self._key("source")
        witness_key = self._key("witness")
        gate_key = self._key("gate")
        source_method = "did:openline:local-tool-adapter#source-1"
        trust = TrustStore.from_mapping(
            {
                "keys": {
                    source_method: {
                        "public_key": public_key_hex(source_key),
                        "roles": ["source"],
                        "independence": "operator",
                        "controller": "openline-local-tool-adapter",
                    },
                    public_key_hex(witness_key): {
                        "public_key": public_key_hex(witness_key),
                        "roles": ["outcome"],
                        "independence": "receiver",
                        "controller": "openline-local-receiver",
                    },
                }
            }
        )

        nonce = secrets.token_hex(10)
        run_id = f"authorized-tool-{nonce}"
        session_id = f"session-{nonce}"
        action_id = f"action-{nonce}"
        artifact = self.evidence_dir / f"authority-{nonce}.json"
        artifact.write_text(
            json.dumps(checked, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        artifact_hash = sha256_hex(artifact.read_bytes())
        source = self._source_receipt(
            key=source_key,
            method=source_method,
            run_id=run_id,
            session_id=session_id,
            action_id=action_id,
            response_hash=artifact_hash,
            now=now,
        )
        source_hash = self._source_hash(source)
        session = SessionLedger(self.session_path)
        binding = session.issue_challenge(
            run_id=run_id,
            session_id=session_id,
            expected_source_hash=source_hash,
        )
        outcome = issue_outcome_receipt(
            source_receipt_hash=source_hash,
            outcome_status="pass",
            harmful=False,
            evidence_hash=artifact_hash,
            witness_id="openline-local-receiver",
            rollback_supported=False,
            key=witness_key,
        )
        action = {
            "tool": proposal["tool"],
            "target": proposal["target"],
            "settings": checked["commit_settings"],
            "run_id": run_id,
            "capsule_hash": canonical_hash(
                {
                    "profile": TOOL_ADAPTER_PROFILE,
                    "proposal_hash": checked["proposal_hash"],
                    "compiler_result_hash": checked["result_hash"],
                    "run_id": run_id,
                }
            ),
            "evidence_hashes": [artifact_hash],
        }
        ttl = min(int(checked["max_authorization_ttl_seconds"]), 60)
        deadline = min(
            now.astimezone(timezone.utc) + timedelta(seconds=ttl),
            _parse_time(str(checked["valid_until"])),
        )
        ttl = max(1, int((deadline - now.astimezone(timezone.utc)).total_seconds()))
        execution_policy = PolicySpec.from_mapping(
            {
                "policy_id": "openline.authorized-tool.local-execution",
                "version": "1",
                "require_declared_coverage": True,
                "require_outcome_witness": True,
                "required_evidence_ids": ["authority_compiler"],
                "evidence_assertions": [
                    {
                        "evidence_id": "authority_compiler",
                        "path": "decision",
                        "op": "equals",
                        "value": "COMMIT_ELIGIBLE",
                    }
                ],
                "metadata": {
                    "verified_commit": {
                        "required": True,
                        "tool": action["tool"],
                        "target": action["target"],
                        "settings_hash": settings_hash(action["settings"]),
                        "run_id": run_id,
                        "capsule_hash": action["capsule_hash"],
                        "evidence_hashes": action["evidence_hashes"],
                        "max_ttl_seconds": ttl,
                    }
                },
            }
        )
        one_use_code = issue_one_use_code()
        request = {
            "schema": "openline.proof_to_policy.request.v0.2",
            "request_id": f"request-{nonce}",
            "action_type": "tool_call",
            "claim": "The Authority-Compiler-qualified exact tool call may execute once.",
            "source_receipts": [source],
            "binding": binding,
            "evidence": [
                {
                    "id": "authority_compiler",
                    "artifact_path": str(artifact.relative_to(self.root)),
                    "content_hash": artifact_hash,
                    "source_commitment_path": "credentialSubject.outcome.response_hash",
                }
            ],
            "outcome_receipt": outcome,
            "commit_request": {
                **action,
                "policy_hash": execution_policy.policy_hash,
                "expires_at": _iso(deadline),
                "one_use_code": one_use_code,
            },
        }
        receipt = evaluate_request(
            request,
            policy=execution_policy,
            trust_store=trust,
            signing_key=gate_key,
            issuer_id="openline-local-authority-runtime",
            decision_path=self.decision_log,
            session_ledger=session,
            base_dir=self.root,
            now=now,
        )
        if receipt.get("decision") != "COMMIT" or receipt.get("verdict") != "VERIFIED":
            raise AuthorizationBlocked(
                str(receipt.get("decision", "DENY")),
                ["verified_commit_not_issued"],
                compilation=checked,
                decision_receipt=receipt,
            )
        action["policy_hash"] = execution_policy.policy_hash
        ledger = VerifiedCommitLedger(self.commit_ledger_path)
        execution = compiler.execute_once(
            ledger,
            receipt,
            action,
            proposal,
            checked,
            one_use_code=one_use_code,
            trusted_gate_keys=[public_key_hex(gate_key)],
            executor=lambda _tool, _target, _settings: executor(),
            now=now,
            attempt_label=str(proposal["proposal_id"]),
        )
        if execution.get("authorized") is not True:
            raise AuthorizationBlocked(
                "DENY",
                execution.get("reason_codes", ["execution_preflight_blocked"]),
                compilation=checked,
                decision_receipt=receipt,
            )
        return AuthorizedValue(
            value=execution.get("tool_result"),
            decision_receipt=receipt,
            compilation=checked,
            execution=execution,
        )


def authorize(
    *,
    policy: str | Path | Mapping[str, Any],
    target: str | Callable[[ToolCallContext], str],
    semantics: Callable[[ToolCallContext], Mapping[str, Any]],
    state_source: Callable[[ToolCallContext], Mapping[str, Any] | str],
    evidence_sources: Mapping[str, Callable[[ToolCallContext], Any]],
    tool: str | None = None,
    producer_model: str = "untrusted-agent",
    objective: str = "execute the requested tool call",
    runtime: Any | None = None,
    runtime_dir: str | Path = ".openline/runtime",
    return_receipt: bool = False,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Guard a normal Python function at the exact tool boundary.

    ``evidence_sources`` are receiver-owned callables keyed by requirement ID.
    LLM/model output must never be routed into those callbacks as trusted data.
    """

    if not callable(semantics) or not callable(state_source):
        raise ToolAdapterError("resolver_not_callable")
    if not isinstance(evidence_sources, Mapping) or not all(
        isinstance(key, str) and key and callable(provider)
        for key, provider in evidence_sources.items()
    ):
        raise ToolAdapterError("evidence_sources_invalid")
    bundle = _load_bundle(policy)
    mandate = bundle["mandate"]
    permission_policy = bundle["permission_policy"]
    producer_id = mandate.get("agent_id")
    if not isinstance(producer_id, str) or not producer_id:
        raise ToolAdapterError("mandate_agent_id_invalid")
    if not isinstance(producer_model, str) or not producer_model:
        raise ToolAdapterError("producer_model_invalid")
    if not isinstance(objective, str) or not objective:
        raise ToolAdapterError("objective_invalid")

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        signature = inspect.signature(function)
        tool_name = tool or function.__name__
        active_runtime = runtime or LocalAuthorityRuntime(runtime_dir)

        def target_for(arguments: Mapping[str, Any], proposal_id: str) -> str:
            if isinstance(target, str):
                if not target:
                    raise ToolAdapterError("target_invalid")
                return target
            provisional = ToolCallContext(
                tool=tool_name,
                target="pending",
                arguments=_json_copy(arguments),
                proposal_id=proposal_id,
                producer_id=producer_id,
                producer_model=producer_model,
                objective=objective,
            )
            resolved = target(provisional)
            if not isinstance(resolved, str) or not resolved:
                raise ToolAdapterError("target_invalid")
            return resolved

        def context_for(proposal: Mapping[str, Any]) -> ToolCallContext:
            return _context_from_proposal(proposal)

        def effect_resolver(proposal: Mapping[str, Any]) -> Mapping[str, Any]:
            return semantics(context_for(proposal))

        def state_resolver(proposal: Mapping[str, Any]) -> str:
            value = state_source(context_for(proposal))
            if _is_hash(value):
                return str(value)
            if not isinstance(value, Mapping):
                raise ToolAdapterError("state_source_result_invalid")
            return canonical_hash(_json_copy(dict(value)))

        def evidence_resolver(
            proposal: Mapping[str, Any], obligation: Mapping[str, Any], now: datetime
        ) -> Sequence[Mapping[str, Any]]:
            call = context_for(proposal)
            evidence: list[Mapping[str, Any]] = []
            requirements = obligation.get("requirements", [])
            if not isinstance(requirements, list):
                raise ToolAdapterError("obligation_requirements_invalid")
            for requirement in requirements:
                if not isinstance(requirement, Mapping):
                    raise ToolAdapterError("obligation_requirement_invalid")
                rid = requirement.get("requirement_id")
                if not isinstance(rid, str) or not rid:
                    raise ToolAdapterError("obligation_requirement_id_invalid")
                provider = evidence_sources.get(rid)
                if provider is None:
                    continue
                normalized = _normalize_provider_result(
                    provider(call),
                    default_issuer=rid,
                    max_age_seconds=int(requirement["max_age_seconds"]),
                    now=now,
                )
                if normalized is None:
                    continue
                issuer = normalized.issuer_id or rid
                issued = normalized.issued_at or now
                artifact_hash = canonical_hash(
                    {
                        "profile": "openline.tool-evidence-artifact/v1",
                        "requirement_id": rid,
                        "issuer_id": issuer,
                        "payload": dict(normalized.payload),
                    }
                )
                verification_hash = canonical_hash(
                    {
                        "profile": "openline.tool-evidence-verification/v1",
                        "requirement_id": rid,
                        "issuer_id": issuer,
                        "artifact_hash": artifact_hash,
                        "verified_at": _iso(now),
                    }
                )
                evidence.append(
                    {
                        "profile": "permission_evidence/v1",
                        "requirement_id": rid,
                        "kind": requirement["kind"],
                        "subject_hash": obligation["effect_hash"],
                        "issuer_id": issuer,
                        "issued_at": _iso(issued),
                        "expires_at": _iso(
                            issued + timedelta(seconds=int(normalized.expires_in_seconds or 1))
                        ),
                        "artifact_hash": artifact_hash,
                        "verification_receipt_hash": verification_hash,
                        "receiver_verification_status": (
                            "VERIFIED" if normalized.verified else "UNVERIFIED"
                        ),
                        "revoked": bool(normalized.revoked),
                    }
                )
            return evidence

        compiler = AuthorityCompiler(
            mandate=mandate,
            permission_policy=permission_policy,
            effect_semantics_resolver=effect_resolver,
            state_resolver=state_resolver,
            evidence_resolver=evidence_resolver,
            compiler_id=f"openline.tool-adapter:{tool_name}",
            effect_resolver_id=f"tool-adapter:{tool_name}:semantics/v1",
            state_resolver_id=f"tool-adapter:{tool_name}:state/v1",
            evidence_resolver_id=f"tool-adapter:{tool_name}:evidence/v1",
        )

        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            bound = signature.bind(*args, **kwargs)
            bound.apply_defaults()
            frozen_arguments = _json_copy(dict(bound.arguments))
            proposal_id = f"tool-{secrets.token_hex(12)}"
            resolved_target = target_for(frozen_arguments, proposal_id)
            provisional = {
                "profile": "decision_proposal/v1",
                "proposal_id": proposal_id,
                "producer_id": producer_id,
                "producer_model": producer_model,
                "objective": objective,
                "tool": tool_name,
                "target": resolved_target,
                "settings": frozen_arguments,
                "state_hash": "00" * 32,
                "advisory_hash": canonical_hash(
                    {
                        "producer_model": producer_model,
                        "objective": objective,
                        "authority": "NONE",
                    }
                ),
            }
            initial_state = state_resolver(provisional)
            proposal = {**provisional, "state_hash": initial_state}
            now = _utc_now()
            compilation = compiler.compile(proposal, now=now)
            if hasattr(active_runtime, "record_compilation") and callable(
                active_runtime.record_compilation
            ):
                active_runtime.record_compilation(compilation)
            if compilation["decision"] != "COMMIT_ELIGIBLE":
                raise AuthorizationBlocked(
                    compilation["decision"],
                    compilation["reason_codes"],
                    compilation=compilation,
                )

            # Reconstruct the call from the frozen JSON values that were hashed,
            # rather than executing with mutable caller-owned objects.
            frozen_bound = inspect.BoundArguments(signature, frozen_arguments)

            def execute_exact() -> Any:
                return function(*frozen_bound.args, **frozen_bound.kwargs)

            if not hasattr(active_runtime, "execute") or not callable(active_runtime.execute):
                raise ToolAdapterError("runtime_invalid")
            authorized = active_runtime.execute(
                compiler=compiler,
                proposal=proposal,
                compilation=compilation,
                executor=execute_exact,
                now=now,
            )
            if not isinstance(authorized, AuthorizedValue):
                raise ToolAdapterError("runtime_result_invalid")
            return authorized if return_receipt else authorized.value

        wrapped.__openline_guarded__ = True  # type: ignore[attr-defined]
        wrapped.openline_compiler = compiler  # type: ignore[attr-defined]
        wrapped.openline_runtime = active_runtime  # type: ignore[attr-defined]
        wrapped.openline_policy_bundle = _json_copy(bundle)  # type: ignore[attr-defined]
        return wrapped

    return decorate
