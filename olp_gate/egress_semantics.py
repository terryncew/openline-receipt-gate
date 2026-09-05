"""EGRESS-SEMANTICS-001: receiver-owned effect contracts before dispatch.

This module does not infer remote side effects from HTTP verbs or responses and
does not implement an HTTP client, DNS resolver, TLS stack, or socket sandbox.

It defines one narrow interposition seam for traffic a receiver deliberately
routes through it:

    transport.prepare(request)
        -> observe the exact destination identity without dispatching the
           consequential request
    receiver contract + Receipt Gate authorization
        -> authorize the receiver-classified effect for that exact hop
    transport.dispatch(token)
        -> send the request on the same prepared receiver-owned transport handle

Every redirect is treated as a new request/hop and therefore goes through a new
contract lookup, destination observation, and Receipt Gate authorization.

Traffic that bypasses this adapter (raw sockets, another HTTP client, another
process, mutable transport internals, etc.) is outside this proof.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import threading
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from .subject_bound_commit import authorize_subject_bound_owned
from .tool_adapter import AuthorizationBlocked, LocalAuthorityRuntime, ToolCallContext


READ = "READ"
REMOTE_MUTATION = "REMOTE_MUTATION"
_EFFECT_TO_ACTION = {
    READ: "inspect",
    REMOTE_MUTATION: "send",
}
TOOL_NAME = "receiver_egress_dispatch"
EVIDENCE_REQUIREMENT_ID = "egress_contract"


class EgressSemanticsError(ValueError):
    """Invalid receiver configuration, request shape, or transport observation."""


class EgressBlocked(PermissionError):
    """Receiver-side egress enforcement blocked the hop before dispatch."""

    def __init__(self, *reason_codes: str):
        self.reason_codes = tuple(sorted(set(str(item) for item in reason_codes)))
        super().__init__("openline:egress:" + ",".join(self.reason_codes))


def _canonical_json_hash(value: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise EgressSemanticsError("egress_url_invalid")
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise EgressSemanticsError("egress_https_required")
    if parsed.username is not None or parsed.password is not None:
        raise EgressSemanticsError("egress_userinfo_forbidden")
    if parsed.fragment:
        raise EgressSemanticsError("egress_fragment_forbidden")
    hostname = parsed.hostname
    if not isinstance(hostname, str) or not hostname:
        raise EgressSemanticsError("egress_hostname_invalid")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EgressSemanticsError("egress_hostname_ascii_required") from exc
    hostname = hostname.lower()
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise EgressSemanticsError("egress_port_invalid") from exc
    if port <= 0 or port > 65535:
        raise EgressSemanticsError("egress_port_invalid")
    path = parsed.path or "/"
    # Keep the experiment out of URL-normalization ambiguity. The receiver may
    # add a richer canonicalizer later, but this proof uses literal route paths.
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise EgressSemanticsError("egress_dot_segments_forbidden")
    netloc = f"{hostname}:{port}"
    return urlunsplit(("https", netloc, path, parsed.query, ""))


def _hostname_from_canonical_url(value: str) -> str:
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if not isinstance(hostname, str) or not hostname:
        raise EgressSemanticsError("egress_hostname_invalid")
    return hostname.lower()


def _normalize_method(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EgressSemanticsError("egress_method_invalid")
    method = value.strip().upper()
    if not method.isascii() or not method.isalpha():
        raise EgressSemanticsError("egress_method_invalid")
    return method


@dataclass(frozen=True)
class EndpointContract:
    """Receiver-owned semantics for one exact method + endpoint."""

    contract_id: str
    method: str
    url: str
    effect_class: str
    allowed_resolved_endpoints: tuple[str, ...]
    allowed_tls_identities: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "EndpointContract":
        if not isinstance(value, Mapping):
            raise EgressSemanticsError("egress_contract_invalid")
        required = {
            "contract_id",
            "method",
            "url",
            "effect_class",
            "allowed_resolved_endpoints",
            "allowed_tls_identities",
        }
        if set(value) != required:
            raise EgressSemanticsError("egress_contract_shape_invalid")
        contract_id = value.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id:
            raise EgressSemanticsError("egress_contract_id_invalid")
        method = _normalize_method(value.get("method"))
        url = _canonical_url(value.get("url"))
        effect_class = value.get("effect_class")
        if effect_class not in _EFFECT_TO_ACTION:
            raise EgressSemanticsError("egress_effect_class_invalid")

        def normalize_nonempty_strings(name: str) -> tuple[str, ...]:
            raw = value.get(name)
            if (
                not isinstance(raw, list)
                or not raw
                or not all(isinstance(item, str) and item for item in raw)
                or len(set(raw)) != len(raw)
            ):
                raise EgressSemanticsError(f"{name}_invalid")
            return tuple(sorted(raw))

        return cls(
            contract_id=contract_id,
            method=method,
            url=url,
            effect_class=effect_class,
            allowed_resolved_endpoints=normalize_nonempty_strings(
                "allowed_resolved_endpoints"
            ),
            allowed_tls_identities=normalize_nonempty_strings(
                "allowed_tls_identities"
            ),
        )

    @property
    def hostname(self) -> str:
        return _hostname_from_canonical_url(self.url)

    @property
    def contract_hash(self) -> str:
        return _canonical_json_hash(
            {
                "contract_id": self.contract_id,
                "method": self.method,
                "url": self.url,
                "effect_class": self.effect_class,
                "allowed_resolved_endpoints": list(self.allowed_resolved_endpoints),
                "allowed_tls_identities": list(self.allowed_tls_identities),
            }
        )


class EgressContractRegistry:
    """Immutable receiver-owned contract lookup."""

    def __init__(self, contracts: Sequence[EndpointContract | Mapping[str, Any]]):
        normalized: list[EndpointContract] = []
        for item in contracts:
            normalized.append(
                item if isinstance(item, EndpointContract)
                else EndpointContract.from_mapping(item)
            )
        if not normalized:
            raise EgressSemanticsError("egress_contracts_empty")

        by_key: dict[tuple[str, str], EndpointContract] = {}
        ids: set[str] = set()
        for contract in normalized:
            key = (contract.method, contract.url)
            if key in by_key:
                raise EgressSemanticsError("egress_contract_route_duplicate")
            if contract.contract_id in ids:
                raise EgressSemanticsError("egress_contract_id_duplicate")
            by_key[key] = contract
            ids.add(contract.contract_id)

        self._contracts = tuple(sorted(normalized, key=lambda c: c.contract_id))
        self._by_key = by_key

    @property
    def contracts(self) -> tuple[EndpointContract, ...]:
        return self._contracts

    def require(self, method: str, url: str) -> EndpointContract:
        key = (_normalize_method(method), _canonical_url(url))
        contract = self._by_key.get(key)
        if contract is None:
            raise EgressBlocked("egress_contract_missing")
        return contract


def build_egress_policy_bundle(
    mandate: Mapping[str, Any],
    registry: EgressContractRegistry,
    *,
    policy_id: str = "egress-semantics-001",
) -> dict[str, Any]:
    """Project receiver contracts into the existing Decision Permission policy.

    This is not a new policy engine. The returned bundle is consumed by the
    existing authorize_owned / AuthorityCompiler / VerifiedCommit path.
    """

    if not isinstance(mandate, Mapping):
        raise EgressSemanticsError("egress_mandate_invalid")
    if not isinstance(policy_id, str) or not policy_id:
        raise EgressSemanticsError("egress_policy_id_invalid")

    routes = []
    for contract in registry.contracts:
        routes.append(
            {
                "route_id": f"egress-{contract.contract_id}",
                "tool": TOOL_NAME,
                "target": contract.url,
                "requirements": [
                    {
                        "requirement_id": EVIDENCE_REQUIREMENT_ID,
                        "kind": "authority",
                        "accepted_issuers": [EVIDENCE_REQUIREMENT_ID],
                        "max_age_seconds": 60,
                        "independent_from_producer": True,
                    }
                ],
                "unknown_behavior": "QUARANTINE",
                "max_authorization_ttl_seconds": 60,
            }
        )
    return {
        "schema": "openline.authorized_tool_policy.v1",
        "mandate": dict(mandate),
        "permission_policy": {
            "profile": "decision_permission_policy/v1",
            "policy_id": policy_id,
            "version": "1",
            "routes": routes,
        },
    }


@dataclass
class _PreparedState:
    token: str
    request: dict[str, Any]
    contract: EndpointContract
    observation: dict[str, str]
    dispatched: bool = False


class ReceiverEgressAdapter:
    """Mediate one prepared outbound hop at the real dispatch boundary.

    ``transport`` is receiver-owned and must provide:

    * ``prepare(request) -> mapping``. It may resolve/connect/perform TLS, but it
      must not send the consequential HTTP request. The mapping must contain
      token, requested_hostname, resolved_endpoint, sni_hostname, tls_identity.
    * ``dispatch(token) -> mapping``. It sends the request on the exact prepared
      handle represented by token.
    * ``abort(token)``. It closes/discards a prepared handle that was blocked.

    If transport can silently swap what a token means after ``prepare``, that is
    outside this proof; such a transport is not receiver-observed continuity.
    """

    def __init__(
        self,
        *,
        registry: EgressContractRegistry,
        transport: Any,
        policy: Mapping[str, Any],
        mandate_view: Any,
        mandate_slot_id: str,
        subject_source: Callable[[], str],
        runtime: LocalAuthorityRuntime | None = None,
        runtime_dir: str = ".openline/runtime",
        producer_model: str = "untrusted-agent",
        max_redirects: int = 5,
    ) -> None:
        for name in ("prepare", "dispatch", "abort"):
            if not hasattr(transport, name) or not callable(getattr(transport, name)):
                raise EgressSemanticsError(f"egress_transport_{name}_missing")
        if not isinstance(max_redirects, int) or isinstance(max_redirects, bool):
            raise EgressSemanticsError("egress_max_redirects_invalid")
        if max_redirects < 0 or max_redirects > 20:
            raise EgressSemanticsError("egress_max_redirects_invalid")

        self.registry = registry
        self.transport = transport
        self.policy = dict(policy)
        self.mandate_view = mandate_view
        self.mandate_slot_id = mandate_slot_id
        self.subject_source = subject_source
        self.runtime = runtime
        self.runtime_dir = runtime_dir
        self.producer_model = producer_model
        self.max_redirects = max_redirects

        self._prepared: dict[str, _PreparedState] = {}
        self._prepared_lock = threading.RLock()

        self._guarded_dispatch = authorize_subject_bound_owned(
            policy=self.policy,
            mandate_view=self.mandate_view,
            mandate_slot_id=self.mandate_slot_id,
            subject_source=self.subject_source,
            tool=TOOL_NAME,
            target=self._target_for_call,
            semantics=self._semantics_for_call,
            state_source=self._state_for_call,
            evidence_sources={
                EVIDENCE_REQUIREMENT_ID: self._contract_evidence_for_call,
            },
            producer_model=self.producer_model,
            objective="dispatch one receiver-authorized egress hop",
            runtime=self.runtime,
            runtime_dir=self.runtime_dir,
        )(self._dispatch_one)

    def _state_for_token(self, token: Any) -> _PreparedState:
        if not isinstance(token, str) or not token:
            raise EgressSemanticsError("egress_prepared_token_invalid")
        with self._prepared_lock:
            state = self._prepared.get(token)
        if state is None:
            raise EgressSemanticsError("egress_prepared_token_unknown")
        return state

    @staticmethod
    def _validate_prepare_result(
        value: Any,
        contract: EndpointContract,
    ) -> tuple[str, dict[str, str]]:
        if not isinstance(value, Mapping):
            raise EgressBlocked("egress_prepare_result_invalid")
        required = {
            "token",
            "requested_hostname",
            "resolved_endpoint",
            "sni_hostname",
            "tls_identity",
        }
        if set(value) != required:
            raise EgressBlocked("egress_prepare_result_shape_invalid")
        token = value.get("token")
        if not isinstance(token, str) or not token:
            raise EgressBlocked("egress_prepared_token_invalid")

        observation: dict[str, str] = {}
        for name in (
            "requested_hostname",
            "resolved_endpoint",
            "sni_hostname",
            "tls_identity",
        ):
            item = value.get(name)
            if not isinstance(item, str) or not item:
                raise EgressBlocked(f"egress_{name}_invalid")
            observation[name] = item

        reasons: list[str] = []
        if observation["requested_hostname"].lower() != contract.hostname:
            reasons.append("egress_requested_hostname_mismatch")
        if observation["resolved_endpoint"] not in contract.allowed_resolved_endpoints:
            reasons.append("egress_resolved_endpoint_mismatch")
        if observation["sni_hostname"].lower() != contract.hostname:
            reasons.append("egress_sni_mismatch")
        if observation["tls_identity"] not in contract.allowed_tls_identities:
            reasons.append("egress_tls_identity_mismatch")
        if reasons:
            raise EgressBlocked(*reasons)
        return token, observation

    def _context_state(self, call: ToolCallContext) -> _PreparedState:
        token = call.arguments.get("prepared_token")
        state = self._state_for_token(token)
        request = state.request
        comparisons = {
            "method": call.arguments.get("method"),
            "url": call.arguments.get("url"),
            "headers": call.arguments.get("headers"),
            "body": call.arguments.get("body"),
        }
        for name, observed in comparisons.items():
            if observed != request.get(name):
                raise EgressSemanticsError(f"egress_prepared_{name}_changed")
        return state

    def _target_for_call(self, call: ToolCallContext) -> str:
        return self._context_state(call).contract.url

    def _semantics_for_call(self, call: ToolCallContext) -> Mapping[str, Any]:
        state = self._context_state(call)
        # Producer-supplied effect claims are intentionally ignored.
        return {
            "action_type": _EFFECT_TO_ACTION[state.contract.effect_class],
            "disclosures": [],
            "value_cents": 0,
            "delegatee": None,
        }

    def _state_for_call(self, call: ToolCallContext) -> Mapping[str, Any]:
        state = self._context_state(call)
        return {
            "contract_id": state.contract.contract_id,
            "contract_hash": state.contract.contract_hash,
            "effect_class": state.contract.effect_class,
            "authorized_destination": state.contract.url,
            "observation": dict(state.observation),
        }

    def _contract_evidence_for_call(self, call: ToolCallContext) -> Mapping[str, Any]:
        state = self._context_state(call)
        return {
            "contract_id": state.contract.contract_id,
            "contract_hash": state.contract.contract_hash,
            "effect_class": state.contract.effect_class,
            "authorized_destination": state.contract.url,
        }

    def _dispatch_one(
        self,
        prepared_token: str,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: str | None,
        producer_claimed_effect: str | None,
    ) -> Mapping[str, Any]:
        del producer_claimed_effect
        state = self._state_for_token(prepared_token)
        # The exact request metadata has already been frozen and rechecked by
        # Receipt Gate. Mark the receiver-owned prepared token as dispatched
        # immediately before the transport call.
        with self._prepared_lock:
            current = self._prepared.get(prepared_token)
            if current is not state or current.dispatched:
                raise EgressSemanticsError("egress_prepared_token_reused")
            current.dispatched = True
        result = self.transport.dispatch(prepared_token)
        if not isinstance(result, Mapping):
            raise EgressSemanticsError("egress_dispatch_result_invalid")
        return dict(result)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: str | None = None,
        producer_claimed_effect: str | None = None,
    ) -> Mapping[str, Any]:
        current_method = _normalize_method(method)
        current_url = _canonical_url(url)
        frozen_headers = dict(headers or {})
        if not all(
            isinstance(key, str)
            and key
            and isinstance(value, str)
            for key, value in frozen_headers.items()
        ):
            raise EgressSemanticsError("egress_headers_invalid")
        if body is not None and not isinstance(body, str):
            raise EgressSemanticsError("egress_body_invalid")
        if producer_claimed_effect is not None and not isinstance(
            producer_claimed_effect, str
        ):
            raise EgressSemanticsError("egress_producer_claim_invalid")

        for redirect_count in range(self.max_redirects + 1):
            # Contract lookup happens before transport preparation. Unknown
            # destinations do not even earn a prepared receiver handle.
            contract = self.registry.require(current_method, current_url)
            request = {
                "method": current_method,
                "url": current_url,
                "headers": dict(frozen_headers),
                "body": body,
            }
            prepared_raw = self.transport.prepare(dict(request))
            token: str | None = None
            state: _PreparedState | None = None
            try:
                token, observation = self._validate_prepare_result(
                    prepared_raw,
                    contract,
                )
                state = _PreparedState(
                    token=token,
                    request=dict(request),
                    contract=contract,
                    observation=observation,
                )
                with self._prepared_lock:
                    if token in self._prepared:
                        raise EgressBlocked("egress_prepared_token_collision")
                    self._prepared[token] = state

                result = self._guarded_dispatch(
                    token,
                    current_method,
                    current_url,
                    dict(frozen_headers),
                    body,
                    producer_claimed_effect,
                )
            except BaseException:
                if token is None and isinstance(prepared_raw, Mapping):
                    raw_token = prepared_raw.get("token")
                    if isinstance(raw_token, str) and raw_token:
                        token = raw_token
                should_abort = True
                if state is not None and state.dispatched:
                    should_abort = False
                if should_abort and isinstance(token, str) and token:
                    self.transport.abort(token)
                raise
            finally:
                if isinstance(token, str) and token:
                    with self._prepared_lock:
                        self._prepared.pop(token, None)

            redirect_url = result.get("redirect_url")
            if redirect_url is None:
                return dict(result)
            if not isinstance(redirect_url, str) or not redirect_url:
                raise EgressSemanticsError("egress_redirect_url_invalid")
            if redirect_count >= self.max_redirects:
                raise EgressBlocked("egress_redirect_limit_exceeded")

            # A redirect is a new destination. It does not inherit the authority
            # of the previous origin; the next loop performs a fresh contract,
            # destination, and Receipt Gate authorization.
            current_url = _canonical_url(redirect_url)
            redirect_method = result.get("redirect_method", current_method)
            current_method = _normalize_method(redirect_method)

        raise EgressBlocked("egress_redirect_limit_exceeded")
