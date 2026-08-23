from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from olp_gate.tool_adapter import AuthorizationBlocked, LocalAuthorityRuntime, authorize, payment_semantics


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


class ToolAdapterRuntimeIntegration(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='openline-tool-adapter-')
        self.now = datetime.now(timezone.utc)
        self.approved = set()
        self.version = {'C-1': 1}
        self.calls = []
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
                'expires_at': iso(self.now + timedelta(hours=1)),
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

    def tearDown(self):
        self.temp.cleanup()

    def evidence(self, call):
        if call.arguments['amount_cents'] <= 5_000:
            return {'basis': 'under_limit'}
        if call.arguments['customer_id'] in self.approved:
            return {'basis': 'manager'}
        return None

    def state(self, call):
        return {'customer_id': call.arguments['customer_id'], 'version': self.version['C-1']}

    def guarded(self):
        runtime = LocalAuthorityRuntime(self.temp.name)
        @authorize(
            policy=self.bundle,
            tool='process_refund',
            target='refund://process',
            semantics=payment_semantics(),
            state_source=self.state,
            evidence_sources={'refund_authority': self.evidence},
            runtime=runtime,
            return_receipt=True,
        )
        def process_refund(amount_cents: int, customer_id: str):
            self.calls.append((amount_cents, customer_id))
            return {'ok': True, 'amount_cents': amount_cents}
        return process_refund, runtime

    def test_real_gateway_and_verified_commit_execute_exact_call(self):
        guarded, runtime = self.guarded()
        result = guarded(2_500, 'C-1')
        self.assertTrue(result.execution['authorized'])
        self.assertEqual(result.execution['execution_status'], 'completed')
        self.assertEqual(result.decision_receipt['decision'], 'COMMIT')
        self.assertEqual(self.calls, [(2_500, 'C-1')])
        self.assertTrue(runtime.decision_log.exists())
        self.assertTrue(runtime.commit_ledger_path.exists())

    def test_missing_manager_blocks_before_gateway_execution(self):
        guarded, runtime = self.guarded()
        with self.assertRaises(AuthorizationBlocked) as caught:
            guarded(50_000, 'C-1')
        self.assertEqual(caught.exception.decision, 'QUARANTINE')
        self.assertEqual(self.calls, [])
        self.assertFalse(runtime.commit_ledger_path.exists())


if __name__ == '__main__':
    unittest.main()
