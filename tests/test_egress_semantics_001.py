from __future__ import annotations

from datetime import datetime, timedelta, timezone
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from olp_gate.crypto import public_key_hex
from olp_gate.egress_semantics import (
    EgressBlocked,
    EgressContractRegistry,
    EndpointContract,
    READ,
    REMOTE_MUTATION,
    ReceiverEgressAdapter,
    build_egress_policy_bundle,
)
from olp_gate.mandate_owner import MandateOwnerView, issue_mandate_authorization
from olp_gate.tool_adapter import AuthorizationBlocked, LocalAuthorityRuntime


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class SyntheticPreparedTransport:
    """Two-phase receiver transport: prepare observes; dispatch causes effect."""

    def __init__(self, behavior, observations):
        self.behavior = dict(behavior)
        self.observations = dict(observations)
        self.prepared = {}
        self.prepares = []
        self.dispatches = []
        self.aborts = []
        self.remote_mutations = 0
        self.reads = 0
        self._counter = 0

    def prepare(self, request):
        self._counter += 1
        token = f"prepared-{self._counter}"
        url = request["url"]
        self.prepares.append(url)
        self.prepared[token] = dict(request)
        observation = dict(self.observations[url])
        return {"token": token, **observation}

    def dispatch(self, token):
        request = self.prepared.pop(token)
        url = request["url"]
        self.dispatches.append(url)
        behavior = dict(self.behavior[url])
        kind = behavior.pop("kind")
        if kind == "read":
            self.reads += 1
        elif kind == "mutate":
            self.remote_mutations += 1
        elif kind == "redirect":
            self.reads += 1
        else:
            raise AssertionError(kind)
        return behavior

    def abort(self, token):
        self.aborts.append(token)
        self.prepared.pop(token, None)


class EgressSemantics001Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 5, 5, 0, tzinfo=timezone.utc)
        self.owner_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("51" * 32))
        self.owner_id = "alice"
        self.agent_id = "portable-agent"
        self.slot_id = "portable-agent/default"

        self.read_url = "https://read.example:443/data"
        self.mutate_url = "https://legacy.example:443/edit"
        self.redirect_url = "https://start.example:443/go"
        self.other_url = "https://other.example:443/data"

        self.contracts = [
            EndpointContract.from_mapping(
                {
                    "contract_id": "read",
                    "method": "GET",
                    "url": self.read_url,
                    "effect_class": READ,
                    "allowed_resolved_endpoints": ["203.0.113.10:443"],
                    "allowed_tls_identities": ["read.example"],
                }
            ),
            EndpointContract.from_mapping(
                {
                    "contract_id": "legacy-get-write",
                    "method": "GET",
                    "url": self.mutate_url,
                    "effect_class": REMOTE_MUTATION,
                    "allowed_resolved_endpoints": ["203.0.113.20:443"],
                    "allowed_tls_identities": ["legacy.example"],
                }
            ),
            EndpointContract.from_mapping(
                {
                    "contract_id": "redirect-start",
                    "method": "GET",
                    "url": self.redirect_url,
                    "effect_class": READ,
                    "allowed_resolved_endpoints": ["203.0.113.30:443"],
                    "allowed_tls_identities": ["start.example"],
                }
            ),
            EndpointContract.from_mapping(
                {
                    "contract_id": "redirect-other",
                    "method": "GET",
                    "url": self.other_url,
                    "effect_class": READ,
                    "allowed_resolved_endpoints": ["203.0.113.40:443"],
                    "allowed_tls_identities": ["other.example"],
                }
            ),
        ]
        self.registry = EgressContractRegistry(self.contracts)
        self.observations = {
            self.read_url: {
                "requested_hostname": "read.example",
                "resolved_endpoint": "203.0.113.10:443",
                "sni_hostname": "read.example",
                "tls_identity": "read.example",
            },
            self.mutate_url: {
                "requested_hostname": "legacy.example",
                "resolved_endpoint": "203.0.113.20:443",
                "sni_hostname": "legacy.example",
                "tls_identity": "legacy.example",
            },
            self.redirect_url: {
                "requested_hostname": "start.example",
                "resolved_endpoint": "203.0.113.30:443",
                "sni_hostname": "start.example",
                "tls_identity": "start.example",
            },
            self.other_url: {
                "requested_hostname": "other.example",
                "resolved_endpoint": "203.0.113.40:443",
                "sni_hostname": "other.example",
                "tls_identity": "other.example",
            },
        }

    def mandate(self, allowed_targets):
        return {
            "profile": "principal_mandate/v1",
            "mandate_id": "egress-read-only",
            "principal_id": self.owner_id,
            "agent_id": self.agent_id,
            "purpose": "read remote data only",
            "allowed_action_types": ["inspect"],
            "allowed_targets": list(allowed_targets),
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": 0,
            "delegation_allowed": False,
            "expires_at": _iso(self.now + timedelta(days=1)),
            "version": "1",
        }

    def owner_view(self, mandate):
        view = MandateOwnerView(
            {
                self.slot_id: {
                    "owner_id": self.owner_id,
                    "public_key": public_key_hex(self.owner_key),
                }
            }
        )
        authorization = issue_mandate_authorization(
            slot_id=self.slot_id,
            owner_id=self.owner_id,
            mandate=mandate,
            state="ACTIVE",
            sequence=1,
            predecessor_hash=None,
            issued_at=self.now - timedelta(minutes=1),
            expires_at=self.now + timedelta(hours=2),
            key=self.owner_key,
        )
        view.admit(authorization, mandate, now=self.now)
        return view

    def adapter(self, transport, allowed_targets):
        mandate = self.mandate(allowed_targets)
        view = self.owner_view(mandate)
        policy = build_egress_policy_bundle(mandate, self.registry)
        temp = tempfile.TemporaryDirectory(prefix="egress-semantics-001-")
        self.addCleanup(temp.cleanup)
        runtime = LocalAuthorityRuntime(Path(temp.name))
        return ReceiverEgressAdapter(
            registry=self.registry,
            transport=transport,
            policy=policy,
            mandate_view=view,
            mandate_slot_id=self.slot_id,
            subject_source=lambda: self.agent_id,
            runtime=runtime,
            producer_model="fixture-provider",
        )

    def test_read_contract_dispatches_and_truly_does_not_mutate(self):
        transport = SyntheticPreparedTransport(
            {
                self.read_url: {"kind": "read", "status": 200, "body": "ok"},
            },
            self.observations,
        )
        adapter = self.adapter(transport, [self.read_url])
        result = adapter.request("GET", self.read_url)
        self.assertEqual(result["status"], 200)
        self.assertEqual(transport.dispatches, [self.read_url])
        self.assertEqual(transport.reads, 1)
        self.assertEqual(transport.remote_mutations, 0)

    def test_get_remote_mutation_contract_blocks_before_dispatch(self):
        transport = SyntheticPreparedTransport(
            {
                self.mutate_url: {"kind": "mutate", "status": 200, "body": "edited"},
            },
            self.observations,
        )
        # Target is intentionally allowed. The rejection must come from the
        # receiver-owned REMOTE_MUTATION effect contract, not from URL denial.
        adapter = self.adapter(transport, [self.mutate_url])
        with self.assertRaises(AuthorizationBlocked):
            adapter.request("GET", self.mutate_url)
        self.assertEqual(transport.dispatches, [])
        self.assertEqual(transport.remote_mutations, 0)
        self.assertEqual(len(transport.aborts), 1)

    def test_producer_read_only_claim_cannot_override_mutation_contract(self):
        transport = SyntheticPreparedTransport(
            {
                self.mutate_url: {"kind": "mutate", "status": 200, "body": "edited"},
            },
            self.observations,
        )
        adapter = self.adapter(transport, [self.mutate_url])
        with self.assertRaises(AuthorizationBlocked):
            adapter.request(
                "GET",
                self.mutate_url,
                producer_claimed_effect="READ",
            )
        self.assertEqual(transport.dispatches, [])
        self.assertEqual(transport.remote_mutations, 0)

    def test_redirect_is_a_new_destination_authorization(self):
        transport = SyntheticPreparedTransport(
            {
                self.redirect_url: {
                    "kind": "redirect",
                    "status": 302,
                    "redirect_url": self.other_url,
                },
                self.other_url: {"kind": "read", "status": 200, "body": "other"},
            },
            self.observations,
        )
        # The start origin is authorized; redirected origin is deliberately not.
        adapter = self.adapter(transport, [self.redirect_url])
        with self.assertRaises(AuthorizationBlocked):
            adapter.request("GET", self.redirect_url)
        self.assertEqual(transport.dispatches, [self.redirect_url])
        self.assertEqual(transport.prepares, [self.redirect_url, self.other_url])
        self.assertEqual(transport.remote_mutations, 0)

    def test_authorized_redirect_rechecks_and_dispatches_each_hop_once(self):
        transport = SyntheticPreparedTransport(
            {
                self.redirect_url: {
                    "kind": "redirect",
                    "status": 302,
                    "redirect_url": self.other_url,
                },
                self.other_url: {"kind": "read", "status": 200, "body": "other"},
            },
            self.observations,
        )
        adapter = self.adapter(
            transport,
            [self.redirect_url, self.other_url],
        )
        result = adapter.request("GET", self.redirect_url)
        self.assertEqual(result["status"], 200)
        self.assertEqual(
            transport.dispatches,
            [self.redirect_url, self.other_url],
        )

    def test_destination_identity_mismatch_fails_closed_before_dispatch(self):
        cases = {
            "requested_hostname": "attacker.example",
            "resolved_endpoint": "198.51.100.99:443",
            "sni_hostname": "attacker.example",
            "tls_identity": "attacker.example",
        }
        for field, bad_value in cases.items():
            with self.subTest(field=field):
                observations = {
                    key: dict(value) for key, value in self.observations.items()
                }
                observations[self.read_url][field] = bad_value
                transport = SyntheticPreparedTransport(
                    {
                        self.read_url: {"kind": "read", "status": 200, "body": "ok"},
                    },
                    observations,
                )
                adapter = self.adapter(transport, [self.read_url])
                with self.assertRaises(EgressBlocked):
                    adapter.request("GET", self.read_url)
                self.assertEqual(transport.dispatches, [])
                self.assertEqual(len(transport.aborts), 1)

    def test_unknown_destination_blocks_before_transport_prepare(self):
        transport = SyntheticPreparedTransport({}, self.observations)
        adapter = self.adapter(transport, [self.read_url])
        with self.assertRaises(EgressBlocked):
            adapter.request("GET", "https://unknown.example/data")
        self.assertEqual(transport.prepares, [])
        self.assertEqual(transport.dispatches, [])


if __name__ == "__main__":
    unittest.main()
