"""Production-facing authority compiler for OpenLine.

The compiler is an orchestration layer over existing, separately tested
primitives. It does not define a new authorization mechanism and it does not
execute tools.

Untrusted optimizer proposal
    -> receiver-owned mandate semantics
    -> receiver-owned current state
    -> receiver-owned evidence resolution
    -> DPL proof obligation / permission assessment
    -> authority_compiler/v1 settings for Verified Commit

Only Verified Commit may mint and spend the exact, single-use execution
authorization. The compiler result itself carries no execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any, Callable, Mapping, Sequence

from .authority_link import (
    AuthorityLinkError,
    assess_permission,
    canonical_hash,
    compile_obligation,
    compile_verified_commit_settings,
    effect_hash as proposal_effect_hash,
    evidence_hash,
    policy_hash,
    proposal_hash,
    validate_evidence,
    validate_obligation,
    validate_policy,
    validate_proposal,
)
from .mandate import EFFECT_PROFILE, MandateSpec, assess_effect


AUTHORITY_COMPILER_SETTINGS_PROFILE = "authority_compiler/v1"
AUTHORITY_COMPILER_RESULT_SCHEMA = "openline.authority_compiler.result.v1"
AUTHORITY_COMPILER_CONFIG_SCHEMA = "openline.authority_compiler.config.v1"
AUTHORITY_COMPILER_PREFLIGHT_SCHEMA = "openline.authority_compiler.preflight.v1"

_HEX_256 = re.compile(r"^[0-9a-f]{64}$")
_EFFECT_SEMANTIC_KEYS = {"action_type", "disclosures", "value_cents", "delegatee"}

EffectSemanticsResolver = Callable[[Mapping[str, Any]], Mapping[str, Any]]
StateResolver = Callable[[Mapping[str, Any]], str]
EvidenceResolver = Callable[
    [Mapping[str, Any], Mapping[str, Any], datetime],
    Sequence[Mapping[str, Any]],
]


class AuthorityCompilerError(ValueError):
    """Raised when compiler configuration or a compiler artifact is invalid."""


def _parse_time(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorityCompilerError("timestamp_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise AuthorityCompilerError("timestamp_invalid") from exc
    if parsed.tzinfo is None:
        raise AuthorityCompilerError("timestamp_timezone_required")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and _HEX_256.fullmatch(value) is not None


def _validate_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityCompilerError(f"{name}_invalid")
    return value


def _normalize_semantics(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _EFFECT_SEMANTIC_KEYS:
        raise AuthorityCompilerError("effect_semantics_shape_invalid")
    action_type = value.get("action_type")
    if not isinstance(action_type, str) or not action_type:
        raise AuthorityCompilerError("effect_semantics_action_type_invalid")
    disclosures = value.get("disclosures")
    if (
        not isinstance(disclosures, list)
        or not all(isinstance(item, str) and item for item in disclosures)
        or len(set(disclosures)) != len(disclosures)
    ):
        raise AuthorityCompilerError("effect_semantics_disclosures_invalid")
    amount = value.get("value_cents")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
        raise AuthorityCompilerError("effect_semantics_value_cents_invalid")
    delegatee = value.get("delegatee")
    if delegatee is not None and (not isinstance(delegatee, str) or not delegatee):
        raise AuthorityCompilerError("effect_semantics_delegatee_invalid")
    return {
        "action_type": action_type,
        "disclosures": sorted(disclosures),
        "value_cents": amount,
        "delegatee": delegatee,
    }


def _result_with_hash(body: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(body)
    return {**result, "result_hash": canonical_hash(result)}


def validate_compiler_result(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityCompilerError("compiler_result_invalid")
    result = dict(value)
    required = {
        "schema",
        "compiler_id",
        "compiler_config_hash",
        "decision",
        "reason_codes",
        "execution_authority",
        "proposal_hash",
        "proposal_effect_hash",
        "mandate_hash",
        "mandate_effect_hash",
        "permission_policy_hash",
        "obligation_hash",
        "permission_assessment_hash",
        "used_evidence_hashes",
        "commit_settings",
        "commit_settings_hash",
        "valid_until",
        "max_authorization_ttl_seconds",
        "resolver_ids",
        "result_hash",
    }
    if set(result) != required:
        raise AuthorityCompilerError("compiler_result_shape_invalid")
    if result.get("schema") != AUTHORITY_COMPILER_RESULT_SCHEMA:
        raise AuthorityCompilerError("compiler_result_schema_invalid")
    if result.get("decision") not in {"COMMIT_ELIGIBLE", "QUARANTINE", "DENY"}:
        raise AuthorityCompilerError("compiler_result_decision_invalid")
    if result.get("execution_authority") != "NONE_UNTIL_VERIFIED_COMMIT":
        raise AuthorityCompilerError("compiler_result_execution_authority_invalid")
    for name in (
        "compiler_config_hash",
        "proposal_hash",
        "proposal_effect_hash",
        "mandate_hash",
        "mandate_effect_hash",
        "permission_policy_hash",
    ):
        if not _is_hash(result.get(name)):
            raise AuthorityCompilerError(f"compiler_result_{name}_invalid")
    for name in ("obligation_hash", "permission_assessment_hash", "commit_settings_hash"):
        if result.get(name) is not None and not _is_hash(result.get(name)):
            raise AuthorityCompilerError(f"compiler_result_{name}_invalid")
    reasons = result.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or not all(isinstance(item, str) and item for item in reasons)
        or len(set(reasons)) != len(reasons)
    ):
        raise AuthorityCompilerError("compiler_result_reason_codes_invalid")
    evidence_hashes = result.get("used_evidence_hashes")
    if (
        not isinstance(evidence_hashes, list)
        or not all(_is_hash(item) for item in evidence_hashes)
        or len(set(evidence_hashes)) != len(evidence_hashes)
    ):
        raise AuthorityCompilerError("compiler_result_evidence_hashes_invalid")
    ttl = result.get("max_authorization_ttl_seconds")
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0:
        raise AuthorityCompilerError("compiler_result_ttl_invalid")
    if result["decision"] == "COMMIT_ELIGIBLE":
        if not isinstance(result.get("commit_settings"), Mapping):
            raise AuthorityCompilerError("compiler_result_commit_settings_missing")
        if result.get("valid_until") is None or ttl <= 0:
            raise AuthorityCompilerError("compiler_result_authorization_window_invalid")
        _parse_time(result["valid_until"])
    else:
        if result.get("commit_settings") is not None:
            raise AuthorityCompilerError("compiler_result_noncommit_has_settings")
        if result.get("commit_settings_hash") is not None:
            raise AuthorityCompilerError("compiler_result_noncommit_has_settings_hash")
        if result.get("valid_until") is not None or ttl != 0:
            raise AuthorityCompilerError("compiler_result_noncommit_has_authorization_window")
    observed = result.pop("result_hash", None)
    expected = canonical_hash(result)
    if observed != expected:
        raise AuthorityCompilerError("compiler_result_hash_mismatch")
    return {**result, "result_hash": expected}


@dataclass(frozen=True)
class AuthorityCompiler:
    """Receiver-owned compiler from an untrusted proposal to commit eligibility.

    The three resolver callables are application adapters and MUST be controlled
    by the receiver. They are intentionally supplied at construction rather
    than in ``compile`` so the optimizer cannot choose its own mandate semantics,
    evidence source, or current-state view.
    """

    mandate: MandateSpec | Mapping[str, Any]
    permission_policy: Mapping[str, Any]
    effect_semantics_resolver: EffectSemanticsResolver
    state_resolver: StateResolver
    evidence_resolver: EvidenceResolver
    compiler_id: str = "openline.authority-compiler"
    effect_resolver_id: str = "receiver.effect-semantics/v1"
    state_resolver_id: str = "receiver.current-state/v1"
    evidence_resolver_id: str = "receiver.permission-evidence/v1"

    def __post_init__(self) -> None:
        mandate = (
            self.mandate
            if isinstance(self.mandate, MandateSpec)
            else MandateSpec.from_mapping(self.mandate)
        )
        policy = validate_policy(self.permission_policy)
        object.__setattr__(self, "mandate", mandate)
        object.__setattr__(self, "permission_policy", policy)
        for name in (
            "compiler_id",
            "effect_resolver_id",
            "state_resolver_id",
            "evidence_resolver_id",
        ):
            _validate_id(getattr(self, name), name)
        for name in (
            "effect_semantics_resolver",
            "state_resolver",
            "evidence_resolver",
        ):
            if not callable(getattr(self, name)):
                raise AuthorityCompilerError(f"{name}_not_callable")

    @property
    def config(self) -> dict[str, Any]:
        return {
            "schema": AUTHORITY_COMPILER_CONFIG_SCHEMA,
            "compiler_id": self.compiler_id,
            "mandate_hash": self.mandate.mandate_hash,
            "permission_policy_hash": policy_hash(self.permission_policy),
            "resolver_ids": {
                "effect_semantics": self.effect_resolver_id,
                "current_state": self.state_resolver_id,
                "permission_evidence": self.evidence_resolver_id,
            },
        }

    @property
    def config_hash(self) -> str:
        return canonical_hash(self.config)

    def _mandate_effect(self, proposal: Mapping[str, Any]) -> dict[str, Any]:
        normalized = validate_proposal(proposal)
        semantics = _normalize_semantics(self.effect_semantics_resolver(normalized))
        return {
            "profile": EFFECT_PROFILE,
            "effect_id": normalized["proposal_id"],
            "mandate_id": self.mandate.mandate_id,
            "principal_id": self.mandate.principal_id,
            "agent_id": self.mandate.agent_id,
            "purpose": self.mandate.purpose,
            "action_type": semantics["action_type"],
            "target": normalized["target"],
            "disclosures": semantics["disclosures"],
            "value_cents": semantics["value_cents"],
            "delegatee": semantics["delegatee"],
            "producer_model": normalized["producer_model"],
        }

    def _base_result(
        self,
        proposal: Mapping[str, Any],
        mandate_assessment: Mapping[str, Any],
        *,
        decision: str,
        reason_codes: Sequence[str],
        obligation_hash: str | None = None,
        permission_assessment_hash: str | None = None,
        used_evidence_hashes: Sequence[str] = (),
        commit_settings: Mapping[str, Any] | None = None,
        valid_until: datetime | None = None,
        ttl_seconds: int = 0,
    ) -> dict[str, Any]:
        normalized = validate_proposal(proposal)
        settings_value = dict(commit_settings) if commit_settings is not None else None
        return _result_with_hash(
            {
                "schema": AUTHORITY_COMPILER_RESULT_SCHEMA,
                "compiler_id": self.compiler_id,
                "compiler_config_hash": self.config_hash,
                "decision": decision,
                "reason_codes": sorted(set(reason_codes)),
                "execution_authority": "NONE_UNTIL_VERIFIED_COMMIT",
                "proposal_hash": proposal_hash(normalized),
                "proposal_effect_hash": proposal_effect_hash(normalized),
                "mandate_hash": self.mandate.mandate_hash,
                "mandate_effect_hash": str(mandate_assessment["effect_hash"]),
                "permission_policy_hash": policy_hash(self.permission_policy),
                "obligation_hash": obligation_hash,
                "permission_assessment_hash": permission_assessment_hash,
                "used_evidence_hashes": sorted(set(used_evidence_hashes)),
                "commit_settings": settings_value,
                "commit_settings_hash": (
                    canonical_hash(settings_value) if settings_value is not None else None
                ),
                "valid_until": _iso(valid_until) if valid_until is not None else None,
                "max_authorization_ttl_seconds": ttl_seconds,
                "resolver_ids": self.config["resolver_ids"],
            }
        )

    def _authorization_deadline(
        self,
        obligation: Mapping[str, Any],
        evidence: Sequence[Mapping[str, Any]],
        assessment: Mapping[str, Any],
        *,
        now: datetime,
    ) -> datetime:
        now_utc = now.astimezone(timezone.utc)
        deadlines = [
            now_utc + timedelta(seconds=int(obligation["max_authorization_ttl_seconds"])),
            _parse_time(self.mandate.expires_at),
        ]
        requirements = {
            item["requirement_id"]: item for item in obligation["requirements"]
        }
        by_hash: dict[str, dict[str, Any]] = {}
        for raw in evidence:
            normalized = validate_evidence(raw)
            by_hash[evidence_hash(normalized)] = normalized
        for digest in assessment.get("used_evidence_hashes", []):
            item = by_hash.get(digest)
            if item is None:
                raise AuthorityCompilerError("selected_evidence_not_resolved")
            requirement = requirements.get(item["requirement_id"])
            if requirement is None:
                raise AuthorityCompilerError("selected_evidence_requirement_unknown")
            issued = _parse_time(item["issued_at"])
            deadlines.append(_parse_time(item["expires_at"]))
            deadlines.append(
                issued + timedelta(seconds=int(requirement["max_age_seconds"]))
            )
        return min(deadlines)

    def compile(self, proposal: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
        """Compile an untrusted proposal into a receiver-owned permission result."""
        normalized = validate_proposal(proposal)
        if normalized["producer_id"] != self.mandate.agent_id:
            # Build the receiver-owned effect anyway so the result remains fully
            # bound and auditable, but never let an unmandated producer proceed.
            effect = self._mandate_effect(normalized)
            mandate_assessment = assess_effect(self.mandate, effect, now=now)
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="DENY",
                reason_codes=["proposal_producer_not_mandated"],
            )

        effect = self._mandate_effect(normalized)
        mandate_assessment = assess_effect(self.mandate, effect, now=now)
        if not mandate_assessment["allowed"]:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="DENY",
                reason_codes=[
                    f"mandate:{reason}" for reason in mandate_assessment["reason_codes"]
                ],
            )

        try:
            obligation = compile_obligation(self.permission_policy, normalized)
        except PermissionError:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="DENY",
                reason_codes=["proposal_route_not_authorized"],
            )

        try:
            current_state_hash = self.state_resolver(normalized)
        except BaseException as exc:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="QUARANTINE",
                reason_codes=[f"receiver_state_resolution_failed:{type(exc).__name__}"],
                obligation_hash=obligation["obligation_hash"],
            )
        if not _is_hash(current_state_hash):
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="QUARANTINE",
                reason_codes=["receiver_state_hash_invalid"],
                obligation_hash=obligation["obligation_hash"],
            )

        try:
            evidence = list(self.evidence_resolver(normalized, obligation, now))
        except BaseException as exc:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="QUARANTINE",
                reason_codes=[f"receiver_evidence_resolution_failed:{type(exc).__name__}"],
                obligation_hash=obligation["obligation_hash"],
            )

        try:
            assessment = assess_permission(
                self.permission_policy,
                normalized,
                evidence,
                now=now,
                current_state_hash=current_state_hash,
                obligation=obligation,
            )
        except AuthorityLinkError as exc:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="DENY",
                reason_codes=[f"permission_evidence_invalid:{exc}"],
                obligation_hash=obligation["obligation_hash"],
            )

        if assessment["decision"] != "COMMIT_ELIGIBLE":
            return self._base_result(
                normalized,
                mandate_assessment,
                decision=assessment["decision"],
                reason_codes=assessment["reason_codes"],
                obligation_hash=obligation["obligation_hash"],
                permission_assessment_hash=assessment["assessment_hash"],
                used_evidence_hashes=assessment.get("used_evidence_hashes", []),
            )

        dpl_settings = compile_verified_commit_settings(
            normalized, obligation, assessment
        )
        deadline = self._authorization_deadline(
            obligation, evidence, assessment, now=now
        )
        ttl_seconds = int((deadline - now.astimezone(timezone.utc)).total_seconds())
        if ttl_seconds <= 0:
            return self._base_result(
                normalized,
                mandate_assessment,
                decision="QUARANTINE",
                reason_codes=["authorization_window_closed"],
                obligation_hash=obligation["obligation_hash"],
                permission_assessment_hash=assessment["assessment_hash"],
                used_evidence_hashes=assessment.get("used_evidence_hashes", []),
            )

        settings = {
            "profile": AUTHORITY_COMPILER_SETTINGS_PROFILE,
            "compiler_id": self.compiler_id,
            "compiler_config_hash": self.config_hash,
            "proposal_hash": proposal_hash(normalized),
            "proposal_effect_hash": proposal_effect_hash(normalized),
            "mandate_hash": self.mandate.mandate_hash,
            "mandate_effect_hash": mandate_assessment["effect_hash"],
            "permission_policy_hash": policy_hash(self.permission_policy),
            "obligation_hash": obligation["obligation_hash"],
            "permission_assessment_hash": assessment["assessment_hash"],
            "evidence_receipt_hashes": sorted(
                assessment.get("used_evidence_hashes", [])
            ),
            "valid_until": _iso(deadline),
            "dpl_settings": dpl_settings,
            "effect_settings": normalized["settings"],
        }
        return self._base_result(
            normalized,
            mandate_assessment,
            decision="COMMIT_ELIGIBLE",
            reason_codes=[],
            obligation_hash=obligation["obligation_hash"],
            permission_assessment_hash=assessment["assessment_hash"],
            used_evidence_hashes=assessment.get("used_evidence_hashes", []),
            commit_settings=settings,
            valid_until=deadline,
            ttl_seconds=ttl_seconds,
        )

    def preflight(
        self,
        compilation: Mapping[str, Any],
        proposal: Mapping[str, Any],
        *,
        now: datetime,
    ) -> dict[str, Any]:
        """Receiver-owned execution-time revalidation for Verified Commit.

        ``VerifiedCommitLedger.execute_once`` consumes the one-use authorization
        before invoking this callback. A failed preflight therefore blocks the
        side effect and also prevents stale permission from being replayed.
        """
        try:
            result = validate_compiler_result(compilation)
            normalized = validate_proposal(proposal)
        except (AuthorityCompilerError, AuthorityLinkError) as exc:
            return {
                "allowed": False,
                "reason_codes": [f"compiler_artifact_invalid:{exc}"],
                "evidence": {
                    "schema": AUTHORITY_COMPILER_PREFLIGHT_SCHEMA,
                    "status": "BLOCKED",
                },
            }

        reasons: list[str] = []
        if result["compiler_config_hash"] != self.config_hash:
            reasons.append("compiler_config_changed")
        if result["proposal_hash"] != proposal_hash(normalized):
            reasons.append("proposal_changed_since_compile")
        if result["proposal_effect_hash"] != proposal_effect_hash(normalized):
            reasons.append("effect_changed_since_compile")
        valid_until = _parse_time(result["valid_until"]) if result["valid_until"] else None
        if valid_until is None or now.astimezone(timezone.utc) >= valid_until:
            reasons.append("compiler_authorization_window_expired")
        if result["decision"] != "COMMIT_ELIGIBLE":
            reasons.append("compiler_result_not_commit_eligible")

        effect = self._mandate_effect(normalized)
        mandate_assessment = assess_effect(self.mandate, effect, now=now)
        if not mandate_assessment["allowed"]:
            reasons.extend(
                f"mandate:{reason}" for reason in mandate_assessment["reason_codes"]
            )
        if mandate_assessment["effect_hash"] != result["mandate_effect_hash"]:
            reasons.append("mandate_effect_changed")

        try:
            obligation = compile_obligation(self.permission_policy, normalized)
        except PermissionError:
            obligation = None
            reasons.append("proposal_route_not_authorized")
        if obligation is not None and obligation["obligation_hash"] != result["obligation_hash"]:
            reasons.append("obligation_changed_since_compile")

        current_state_hash: str | None = None
        fresh_assessment: Mapping[str, Any] | None = None
        if obligation is not None:
            try:
                current_state_hash = self.state_resolver(normalized)
            except BaseException as exc:
                reasons.append(f"receiver_state_resolution_failed:{type(exc).__name__}")
            if current_state_hash is not None and not _is_hash(current_state_hash):
                reasons.append("receiver_state_hash_invalid")
                current_state_hash = None
            if current_state_hash is not None:
                try:
                    evidence = list(
                        self.evidence_resolver(normalized, obligation, now)
                    )
                    fresh_assessment = assess_permission(
                        self.permission_policy,
                        normalized,
                        evidence,
                        now=now,
                        current_state_hash=current_state_hash,
                        obligation=obligation,
                    )
                except (AuthorityLinkError, AuthorityCompilerError) as exc:
                    reasons.append(f"receiver_preflight_invalid:{exc}")
                except BaseException as exc:
                    reasons.append(
                        f"receiver_evidence_resolution_failed:{type(exc).__name__}"
                    )
        if fresh_assessment is not None and fresh_assessment["decision"] != "COMMIT_ELIGIBLE":
            reasons.extend(fresh_assessment["reason_codes"])

        allowed = not reasons
        evidence_projection = {
            "schema": AUTHORITY_COMPILER_PREFLIGHT_SCHEMA,
            "status": "PASS" if allowed else "BLOCKED",
            "compiler_result_hash": result["result_hash"],
            "compiler_config_hash": self.config_hash,
            "mandate_hash": self.mandate.mandate_hash,
            "permission_policy_hash": policy_hash(self.permission_policy),
            "obligation_hash": obligation["obligation_hash"] if obligation else None,
            "state_hash": current_state_hash,
            "permission_assessment_hash": (
                fresh_assessment.get("assessment_hash")
                if isinstance(fresh_assessment, Mapping)
                else None
            ),
            "used_evidence_hashes": (
                sorted(fresh_assessment.get("used_evidence_hashes", []))
                if isinstance(fresh_assessment, Mapping)
                else []
            ),
        }
        return {
            "allowed": allowed,
            "reason_codes": sorted(set(reasons)),
            "evidence": evidence_projection,
        }

    def execute_once(
        self,
        ledger: Any,
        receipt: Mapping[str, Any],
        action: Mapping[str, Any],
        proposal: Mapping[str, Any],
        compilation: Mapping[str, Any],
        *,
        one_use_code: str,
        trusted_gate_keys: Sequence[str],
        executor: Callable[[str, str, Mapping[str, Any]], Any],
        replay_scope_hash: str | None = None,
        now: datetime | None = None,
        attempt_label: str | None = None,
    ) -> dict[str, Any]:
        """Spend an exact Verified Commit authorization with mandatory recheck.

        This is the production spend path for Authority Compiler output. It
        deliberately delegates all signing, exact-action binding, one-use, and
        replay enforcement to the existing ``VerifiedCommitLedger`` while
        always installing the compiler's receiver-owned fresh preflight.
        """
        checked = validate_compiler_result(compilation)
        if checked["decision"] != "COMMIT_ELIGIBLE":
            raise PermissionError("compiler_result_not_commit_eligible")
        normalized = validate_proposal(proposal)
        if checked["proposal_hash"] != proposal_hash(normalized):
            raise AuthorityCompilerError("proposal_changed_since_compile")
        if action.get("tool") != normalized["tool"]:
            raise AuthorityCompilerError("execution_tool_not_compiled")
        if action.get("target") != normalized["target"]:
            raise AuthorityCompilerError("execution_target_not_compiled")
        if action.get("settings") != checked["commit_settings"]:
            raise AuthorityCompilerError("execution_settings_not_compiled")
        if not hasattr(ledger, "execute_once") or not callable(ledger.execute_once):
            raise AuthorityCompilerError("verified_commit_ledger_invalid")
        check_time = now or datetime.now(timezone.utc)
        return ledger.execute_once(
            receipt,
            action,
            one_use_code=one_use_code,
            trusted_gate_keys=trusted_gate_keys,
            executor=lambda: executor(
                normalized["tool"],
                normalized["target"],
                dict(normalized["settings"]),
            ),
            preflight=lambda: self.preflight(
                checked, normalized, now=check_time
            ),
            replay_scope_hash=replay_scope_hash,
            now=check_time,
            attempt_label=attempt_label,
        )
