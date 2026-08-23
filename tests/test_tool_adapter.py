from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from olp_gate.tool_adapter import (
    AuthorizationBlocked,
    AuthorizedValue,
    EvidenceAssertion,
    ToolAdapterError,
    authorize,
    payment_semantics,
)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


class FakeRuntime:
    def __init__(self):
        self.compilations = []
        self.executions = []
        self.before_preflight = None

    def record_compilation(self, value):
        self.compilations.append(value)

    def execute(self, *, compiler, proposal, compilation, executor, now):
        if self.before_preflight:
            self.before_preflight()
        preflight = compiler.preflight(compilation, proposal, now=now)
        if not preflight['allowed']:
            raise AuthorizationBlocked('DENY', preflight['reason_codes'], compilation=compilation)
        value = executor()
        execution = {'authorized': True, 'tool_result': value, 'execution_status': 'completed'}
        self.executions.append((proposal, compilation, value))
        return AuthorizedValue(
            value=value,
            decision_receipt={'decision': 'COMMIT', 'verdict': 'VERIFIED'},
            compilation=compilation,
            execution=execution,
        )


class ToolAdapterTests(unittest.TestCase):
    def setUp(self):
        now = datetime.now(timezone.utc)
        self.manager_approved = set()
        self.account_version = {'C-1': 1, 'C-2': 1}
        self.calls = []
        self.runtime = FakeRuntime()
        self.bundle = {
            'schema': 'openline.authorized_tool_policy.v1',
            'mandate': {
                'profile': 'principal_mandate/v1',
                'mandate_id': 'refund-mandate',
                'principal_id': 'merchant-001',
                'agent_id': 'refund-agent',
                'purpose': 'customer refunds',
                'allowed_action_types': ['authorize_payment'],
                'allowed_targets': ['refund://process'],
                'allowed_disclosure_classes': [],
                'forbidden_disclosure_classes': [],
                'max_settlement_cents': 0,
                'max_payment_cents': 100_000,
                'delegation_allowed': False,
                'expires_at': iso(now + timedelta(days=1)),
                'version': '1',
            },
            'permission_policy': {
                'profile': 'decision_permission_policy/v1',
                'policy_id': 'refund-permission',
                'version': '1',
                'routes': [{
                    'route_id': 'refund',
                    'tool': 'process_refund',
                    'target': 'refund://process',
                    'requirements': [{
                        'requirement_id': 'refund_authority',
                        'kind': 'authority',
                        'accepted_issuers': ['refund_authority'],
                        'max_age_seconds': 30,
                        'independent_from_producer': True,
                    }],
                    'unknown_behavior': 'QUARANTINE',
                    'max_authorization_ttl_seconds': 30,
                }],
            },
        }

    def authority(self, call):
        amount = call.arguments['amount_cents']
        customer = call.arguments['customer_id']
        if amount <= 5_000:
            return {'basis': 'under_50_limit'}
        if customer in self.manager_approved:
            return {'basis': 'manager_approval', 'customer_id': customer}
        return None

    def state(self, call):
        customer = call.arguments['customer_id']
        return {
            'customer_id': customer,
            'account_version': self.account_version[customer],
            'manager_approved': customer in self.manager_approved,
        }

    def guarded(self, *, return_receipt=False):
        @authorize(
            policy=self.bundle,
            tool='process_refund',
            target='refund://process',
            semantics=payment_semantics('amount_cents'),
            state_source=self.state,
            evidence_sources={'refund_authority': self.authority},
            producer_model='reference-agent',
            runtime=self.runtime,
            return_receipt=return_receipt,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.calls.append((amount_cents, customer_id))
            return {'refunded_cents': amount_cents, 'customer_id': customer_id}
        return process_refund

    def test_under_50_executes(self):
        guarded = self.guarded()
        value = guarded(2_500, 'C-1')
        self.assertEqual(value['refunded_cents'], 2_500)
        self.assertEqual(self.calls, [(2_500, 'C-1')])
        self.assertTrue(guarded.__openline_guarded__)
        self.assertEqual(len(self.runtime.executions), 1)

    def test_500_without_manager_is_blocked_before_function(self):
        guarded = self.guarded()
        with self.assertRaises(AuthorizationBlocked) as caught:
            guarded(amount_cents=50_000, customer_id='C-1')
        self.assertEqual(caught.exception.decision, 'QUARANTINE')
        self.assertTrue(any('requirement_missing:refund_authority' == reason for reason in caught.exception.reason_codes))
        self.assertEqual(self.calls, [])
        self.assertEqual(self.runtime.executions, [])

    def test_500_with_manager_executes(self):
        self.manager_approved.add('C-1')
        guarded = self.guarded()
        value = guarded(amount_cents=50_000, customer_id='C-1')
        self.assertEqual(value['refunded_cents'], 50_000)
        self.assertEqual(self.calls, [(50_000, 'C-1')])

    def test_hard_mandate_cap_still_denies_even_with_manager(self):
        self.manager_approved.add('C-1')
        guarded = self.guarded()
        with self.assertRaises(AuthorizationBlocked) as caught:
            guarded(amount_cents=100_001, customer_id='C-1')
        self.assertEqual(caught.exception.decision, 'DENY')
        self.assertIn('mandate:payment_limit_exceeded', caught.exception.reason_codes)
        self.assertEqual(self.calls, [])

    def test_state_drift_between_compile_and_execution_blocks(self):
        guarded = self.guarded()
        self.runtime.before_preflight = lambda: self.account_version.__setitem__('C-1', 2)
        with self.assertRaises(AuthorizationBlocked) as caught:
            guarded(amount_cents=2_500, customer_id='C-1')
        self.assertIn('state_changed_since_proposal', caught.exception.reason_codes)
        self.assertEqual(self.calls, [])

    def test_evidence_revocation_between_compile_and_execution_blocks(self):
        self.manager_approved.add('C-1')
        revoked = {'value': False}

        def authority(call):
            amount = call.arguments['amount_cents']
            if amount <= 5_000:
                return True
            if call.arguments['customer_id'] not in self.manager_approved:
                return None
            return EvidenceAssertion(
                payload={'basis': 'manager_approval'},
                revoked=revoked['value'],
            )

        @authorize(
            policy=self.bundle,
            tool='process_refund',
            target='refund://process',
            semantics=payment_semantics(),
            state_source=self.state,
            evidence_sources={'refund_authority': authority},
            runtime=self.runtime,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.calls.append((amount_cents, customer_id))
            return True

        self.runtime.before_preflight = lambda: revoked.__setitem__('value', True)
        with self.assertRaises(AuthorizationBlocked) as caught:
            process_refund(50_000, 'C-1')
        self.assertIn('evidence_revoked:refund_authority', caught.exception.reason_codes)
        self.assertEqual(self.calls, [])

    def test_return_receipt_is_opt_in(self):
        guarded = self.guarded(return_receipt=True)
        result = guarded(2_500, 'C-1')
        self.assertIsInstance(result, AuthorizedValue)
        self.assertEqual(result.decision_receipt['decision'], 'COMMIT')
        self.assertEqual(result.value['refunded_cents'], 2_500)

    def test_policy_bundle_can_be_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'policy.json'
            path.write_text(json.dumps(self.bundle), encoding='utf-8')
            @authorize(
                policy=path,
                tool='process_refund',
                target='refund://process',
                semantics=payment_semantics(),
                state_source=self.state,
                evidence_sources={'refund_authority': self.authority},
                runtime=self.runtime,
            )
            def process_refund(amount_cents: int, customer_id: str):
                return amount_cents
            self.assertEqual(process_refund(2_500, 'C-1'), 2_500)

    def test_floats_fail_closed_before_authorization(self):
        guarded = self.guarded()
        with self.assertRaisesRegex(ToolAdapterError, 'tool_argument_float_forbidden|tool_arguments_must_be_json|payment_amount_invalid'):
            guarded(25.5, 'C-1')


if __name__ == '__main__':
    unittest.main()
