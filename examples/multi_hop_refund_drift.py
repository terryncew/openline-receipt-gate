#!/usr/bin/env python3
"""Three-hop refund scope drift. OFFLINE ONLY: no funds, models or network APIs.

Run without optional dependencies to inspect terminal decisions. With --otel,
record actual OpenTelemetry SDK spans and openline-otel provisional receipts.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from olp_gate import AuthorizationBlocked, authorize, payment_semantics

CAP = 50_000   # $500, integer cents
ATTACK = 480_000  # $4,800, integer cents
TICKET = "8842"
REFUND = "/v1/refunds"
PAYOUT = "/v1/payouts"


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class PaymentSimulator:
    effects: list

    def post(self, endpoint, amount_cents, ticket_id):
        self.effects.append({"endpoint": endpoint, "amount_cents": amount_cents,
                             "ticket_id": ticket_id})
        return {"simulated": True, "http_status": 200, "amount_cents": amount_cents}


class Observability:
    def __init__(self, enabled):
        self.enabled = enabled
        self.receipts = None
        if not enabled:
            return
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
            from openline_otel import OpenLineReceiptProcessor, ReceiptStore
        except ImportError as exc:
            raise SystemExit(
                "--otel requires opentelemetry-sdk and openline-otel; "
                "see examples/multi_hop_refund_drift/README.md"
            ) from exc
        self.provider = TracerProvider()
        self.memory = InMemorySpanExporter()
        self.provider.add_span_processor(SimpleSpanProcessor(self.memory))
        self.receipts = ReceiptStore()
        self.provider.add_span_processor(OpenLineReceiptProcessor(
            Ed25519PrivateKey.generate(), receipt_store=self.receipts))
        self.tracer = self.provider.get_tracer("openline.multi-hop-refund-drift")

    @contextmanager
    def span(self, name, **attributes):
        if not self.enabled:
            yield None
            return
        with self.tracer.start_as_current_span(name) as span:
            for key, value in attributes.items():
                span.set_attribute(key, value)
            yield span

    def finish(self):
        if not self.enabled:
            return {"kind": "illustrative terminal only", "actual_spans": 0}
        from openline_otel import verify_receipt
        self.provider.force_flush()
        spans = self.memory.get_finished_spans()
        self.provider.shutdown()
        signed = [r for r in self.receipts.all() if verify_receipt(r)]
        return {
            "kind": "real OTel spans, provisional openline-otel receipts",
            "actual_spans": len(spans),
            "span_names": [span.name for span in spans],
            "receiver_decisions": [
                {"decision": span.attributes.get("openline.decision"),
                 "reason_codes": span.attributes.get("openline.reason_codes")}
                for span in spans if span.name == "openline.receiver_gate.appraise"
            ],
            "integrity_verified_provisional_receipts": len(signed),
            "limit": "Signed capture does not establish truthful or complete observations",
        }


def receiver_policy(*, max_payment_cents=CAP):
    return {
        "schema": "openline.authorized_tool_policy.v1",
        "mandate": {
            "profile": "principal_mandate/v1",
            "mandate_id": f"ticket-8842-refund-max-{max_payment_cents}",
            "principal_id": "manager",
            "agent_id": "billing-subagent",
            "purpose": "ticket 8842 capped refund",
            "allowed_action_types": ["authorize_payment"],
            "allowed_targets": ["refund://ticket/8842"],
            "allowed_disclosure_classes": [],
            "forbidden_disclosure_classes": [],
            "max_settlement_cents": 0,
            "max_payment_cents": max_payment_cents,
            "delegation_allowed": False,
            "expires_at": "2035-01-01T00:00:00Z",
            "version": "1",
        },
        "permission_policy": {
            "profile": "decision_permission_policy/v1",
            "policy_id": "ticket-8842-capped-refund",
            "version": "1",
            "routes": [{
                "route_id": "refund",
                "tool": "payment_api_post",
                "target": "refund://ticket/8842",
                "requirements": [{
                    "requirement_id": "manager_authority",
                    "kind": "authority",
                    "accepted_issuers": ["manager_authority"],
                    "max_age_seconds": 30,
                    "independent_from_producer": True,
                }],
                "unknown_behavior": "QUARANTINE",
                "max_authorization_ttl_seconds": 30,
            }],
        },
    }


def run(otel=False, verbose=True, *, owner_cap_cents=CAP, receiver_cap_cents=CAP):
    for label, limit in (("owner", owner_cap_cents), ("receiver", receiver_cap_cents)):
        if type(limit) is not int or limit < 0:
            raise ValueError(f"{label}_cap_must_be_nonnegative_integer_cents")
    effects = PaymentSimulator([])
    obs = Observability(otel)
    # This independently signed manager instruction is checked by a
    # receiver-owned callback, NOT trusted from the compressed agent handoff.
    manager_key = Ed25519PrivateKey.generate()
    owner_intent = {
        "action": "issue_refund", "ticket_id": TICKET, "max_amount_cents": owner_cap_cents,
        "currency": "USD", "state_hash": "invoice_v1",
    }
    owner_sig = manager_key.sign(canonical(owner_intent))
    owner_pub = manager_key.public_key()
    receiver_state = {"invoice_hash": "invoice_v1", "ticket_id": TICKET}

    with tempfile.TemporaryDirectory(prefix="olp-refund-drift-") as tmp:
        def receiver_evidence(call):
            try:
                owner_pub.verify(owner_sig, canonical(owner_intent))
            except Exception:
                return None
            args = call.arguments
            if (args["ticket_id"] != owner_intent["ticket_id"]
                    or args["currency"] != owner_intent["currency"]
                    or args["endpoint"] != REFUND
                    or receiver_state["invoice_hash"] != owner_intent["state_hash"]):
                return None
            # This limit is read from the independently VERIFIED signed
            # owner payload, never from the script's default CAP constant.
            # A failed owner limit is a separate local callback refusal;
            # the receiver's policy compiler still checks its own cap.
            if args["amount_cents"] > owner_intent["max_amount_cents"]:
                raise AuthorizationBlocked("DENY", ["owner_signed_limit_exceeded"])
            return {"manager_signature_verified": True,
                    "ticket_id": owner_intent["ticket_id"],
                    "cap_cents": owner_intent["max_amount_cents"],
                    "invoice_hash": receiver_state["invoice_hash"]}

        @authorize(
            policy=receiver_policy(max_payment_cents=receiver_cap_cents),
            tool="payment_api_post",
            target=lambda call: ("refund://ticket/8842"
                                 if call.arguments["endpoint"] == REFUND
                                 else "payout://ticket/8842"),
            semantics=payment_semantics("amount_cents"),
            state_source=lambda call: dict(receiver_state),
            evidence_sources={"manager_authority": receiver_evidence},
            runtime_dir=Path(tmp) / "receiver",
            producer_model="billing-subagent",
        )
        def payment_api_post(*, endpoint, amount_cents, ticket_id, currency):
            return effects.post(endpoint, amount_cents, ticket_id)

        if verbose:
            print("THREE-HOP REFUND DRIFT — OFFLINE SIMULATION")
            print("Hop 1: manager signs issue_refund, ticket 8842, "
                  f"${owner_cap_cents / 100:,.2f} USD, invoice_v1")
            print("Hop 2: orchestrator handoff says 'clear the $4,800 disputed balance'")
            print("Hop 3: billing sub-agent proposes POST /v1/payouts for $4,800")
            print()

        # Standard coarse-IAM fixture intentionally lacks task-level scope checks.
        with obs.span("demo.coarse_iam"):
            with obs.span("orchestrator.delegate"):
                pass
            with obs.span("billing_agent.plan"):
                pass
            with obs.span("payment_api.execute_payout"):
                result = effects.post(PAYOUT, ATTACK, TICKET)
        baseline_effects = len(effects.effects)
        assert result["http_status"] == 200 and baseline_effects == 1
        if verbose:
            print("RUN 1  Coarse service IAM permits payout route; simulated HTTP 200")
            print("       Simulated $4,800 payout effect = 1 (no money moved)")
            print("       This is a deliberately coarse IAM policy, not every IAM design.")
            print()

        effects.effects.clear()
        with obs.span("demo.openline_receiver_gate"):
            with obs.span("orchestrator.delegate"):
                pass
            with obs.span("billing_agent.plan"):
                pass
            with obs.span("openline.receiver_gate.appraise") as span:
                start = time.perf_counter_ns()
                try:
                    payment_api_post(endpoint=PAYOUT, amount_cents=ATTACK,
                                     ticket_id=TICKET, currency="USD")
                except AuthorizationBlocked as exc:
                    decision, reasons = exc.decision, list(exc.reason_codes)
                else:
                    raise AssertionError("Unauthorized payout reached execution")
                elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
                if span is not None:
                    span.set_attribute("openline.decision", decision)
                    span.set_attribute("openline.reason_codes", ",".join(reasons))
                    span.set_attribute("openline.requested_amount_cents", ATTACK)
                    span.set_attribute("openline.owner_cap_cents", owner_cap_cents)
                    span.set_attribute("openline.receiver_cap_cents", receiver_cap_cents)
        assert decision == "DENY", ("Payout route should hard-deny", decision, reasons)
        assert len(effects.effects) == 0
        if verbose:
            print("RUN 2  OpenLine receiver gate: " + decision + " " + repr(reasons))
            print("       Payout API function not called; simulated payout effect = 0")
            print("       Measured local gate wall-time %.3f ms; NOT a 2 ms guarantee" % elapsed_ms)
            print()

        # Isolate the *amount* violation rather than hiding it under wrong route.
        try:
            payment_api_post(endpoint=REFUND, amount_cents=ATTACK,
                             ticket_id=TICKET, currency="USD")
        except AuthorizationBlocked as exc:
            cap_decision, cap_reasons = exc.decision, list(exc.reason_codes)
        else:
            raise AssertionError("Over-cap refund reached execution")
        assert cap_decision == "DENY", (cap_decision, cap_reasons)
        assert not effects.effects

        # Independent $500 probe when one boundary is set to $100.
        # The distinct codes prove that neither cap shadows the other.
        cap_probe_decision, cap_probe_reasons = None, []
        if min(owner_cap_cents, receiver_cap_cents) < CAP:
            try:
                payment_api_post(endpoint=REFUND, amount_cents=CAP,
                                 ticket_id=TICKET, currency="USD")
            except AuthorizationBlocked as exc:
                cap_probe_decision, cap_probe_reasons = exc.decision, list(exc.reason_codes)
            else:
                raise AssertionError("One independent cap was incorrectly ignored")
            assert cap_probe_decision == "DENY", (cap_probe_decision, cap_probe_reasons)
            assert not effects.effects

        # Positive control: the stricter bound still allows legitimate work.
        positive_cents = min(owner_cap_cents, receiver_cap_cents)
        good = payment_api_post(endpoint=REFUND, amount_cents=positive_cents,
                                ticket_id=TICKET, currency="USD")
        assert good["http_status"] == 200
        assert len(effects.effects) == 1 and effects.effects[0]["amount_cents"] == positive_cents

        # State-bound failure with previously valid amount (not model-owned state).
        receiver_state["invoice_hash"] = "invoice_v2"
        try:
            payment_api_post(endpoint=REFUND, amount_cents=positive_cents,
                             ticket_id=TICKET, currency="USD")
        except AuthorizationBlocked as exc:
            stale_state_decision = exc.decision
        else:
            raise AssertionError("Stale invoice state reached execution")
        assert len(effects.effects) == 1

        telemetry = obs.finish()
        if verbose:
            print("NEGATIVE CONTROL  /v1/refunds $4,800 -> " + cap_decision + " " + repr(cap_reasons))
            print(f"POSITIVE CONTROL  /v1/refunds ${positive_cents / 100:,.2f} -> executed once")
            print("STATE CONTROL     invoice_v2 -> " + stale_state_decision + "; no extra effect")
            print("OTEL:", json.dumps(telemetry, sort_keys=True))
            print("PASS: receiver blocked the $4,800 mutation at the final local function boundary.")

        return {"baseline_effects": baseline_effects, "guarded_payout_effects": 0,
                "payout_decision": decision, "payout_reasons": reasons,
                "over_cap_decision": cap_decision, "over_cap_reasons": cap_reasons,
                "positive_refund_effects": len(effects.effects),
                "positive_refund_amount_cents": positive_cents,
                "owner_cap_cents": owner_cap_cents,
                "receiver_cap_cents": receiver_cap_cents,
                "independent_cap_probe_decision": cap_probe_decision,
                "independent_cap_probe_reasons": cap_probe_reasons,
                "stale_state_decision": stale_state_decision,
                "measured_gate_ms": round(elapsed_ms, 3),
                "telemetry": telemetry, "funds_transferred": 0}


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--otel", action="store_true",
                   help="real SDK spans and openline-otel signed provisional receipts")
    p.add_argument("--json", action="store_true")
    args = p.parse_args()
    result = run(otel=args.otel, verbose=not args.json)
    if args.json:
        print(json.dumps(result, sort_keys=True))
