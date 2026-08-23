from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import unittest

from olp_gate.authority_compiler import (
    AUTHORITY_COMPILER_SETTINGS_PROFILE,
    AuthorityCompiler,
    AuthorityCompilerError,
    validate_compiler_result,
)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def clone(value):
    return json.loads(json.dumps(value))


class FakeVerifiedCommitLedger:
    def __init__(self):
        self.calls = []

    def execute_once(self, receipt, action, **kwargs):
        self.calls.append(kwargs)
        preflight = kwargs['preflight']()
        if not preflight['allowed']:
            return {
                'authorized': False,
                'permission_consumed': True,
                'reason_codes': preflight['reason_codes'],
                'execution_status': 'preflight_blocked',
            }
        return {
            'authorized': True,
            'permission_consumed': True,
            'reason_codes': [],
            'execution_status': 'completed',
            'tool_result': kwargs['executor'](),
        }


class AuthorityCompilerTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 8, 23, 20, 0, 0, tzinfo=timezone.utc)
        self.state_hash = '11' * 32
        self.mandate = {
            'profile': 'principal_mandate/v1',
            'mandate_id': 'mandate-001',
            'principal_id': 'principal-001',
            'agent_id': 'agent-001',
            'purpose': 'settle approved vendor obligations',
            'allowed_action_types': ['authorize_payment'],
            'allowed_targets': ['vendor://acme'],
            'allowed_disclosure_classes': [],
            'forbidden_disclosure_classes': [],
            'max_settlement_cents': 0,
            'max_payment_cents': 1_000_000,
            'delegation_allowed': False,
            'expires_at': iso(self.now + timedelta(minutes=10)),
            'version': '1',
        }
        self.policy = {
            'profile': 'decision_permission_policy/v1',
            'policy_id': 'settlement-policy',
            'version': '1',
            'routes': [{
                'route_id': 'pay-acme',
                'tool': 'payments.authorize',
                'target': 'vendor://acme',
                'requirements': [
                    {
                        'requirement_id': 'liquidity_gt_50000',
                        'kind': 'evidence',
                        'accepted_issuers': ['treasury'],
                        'max_age_seconds': 60,
                        'independent_from_producer': True,
                    },
                    {
                        'requirement_id': 'tier1_vendor',
                        'kind': 'authority',
                        'accepted_issuers': ['vendor-master'],
                        'max_age_seconds': 3600,
                        'independent_from_producer': True,
                    },
                ],
                'unknown_behavior': 'QUARANTINE',
                'max_authorization_ttl_seconds': 120,
            }],
        }
        self.proposal = {
            'profile': 'decision_proposal/v1',
            'proposal_id': 'proposal-001',
            'producer_id': 'agent-001',
            'producer_model': 'optimizer-a',
            'objective': 'minimize settlement cost',
            'tool': 'payments.authorize',
            'target': 'vendor://acme',
            'settings': {'amount_cents': 500_000, 'timing': 'immediate'},
            'state_hash': self.state_hash,
            'advisory_hash': 'aa' * 32,
        }
        self.evidence_mode = 'clean'
        self.current_state = self.state_hash

    def semantics(self, proposal):
        return {
            'action_type': 'authorize_payment',
            'disclosures': [],
            'value_cents': proposal['settings']['amount_cents'],
            'delegatee': None,
        }

    def state(self, proposal):
        return self.current_state

    def evidence(self, proposal, obligation, now):
        if self.evidence_mode == 'missing':
            return []
        subject = obligation['effect_hash']
        common = {
            'profile': 'permission_evidence/v1',
            'subject_hash': subject,
            'receiver_verification_status': 'VERIFIED',
            'revoked': False,
        }
        liquidity = {
            **common,
            'requirement_id': 'liquidity_gt_50000',
            'kind': 'evidence',
            'issuer_id': 'treasury',
            'issued_at': iso(self.now - timedelta(seconds=10)),
            'expires_at': iso(self.now + timedelta(seconds=30)),
            'artifact_hash': '21' * 32,
            'verification_receipt_hash': '31' * 32,
        }
        tier = {
            **common,
            'requirement_id': 'tier1_vendor',
            'kind': 'authority',
            'issuer_id': 'vendor-master',
            'issued_at': iso(self.now - timedelta(seconds=10)),
            'expires_at': iso(self.now + timedelta(minutes=5)),
            'artifact_hash': '22' * 32,
            'verification_receipt_hash': '32' * 32,
        }
        if self.evidence_mode == 'self':
            tier['issuer_id'] = 'agent-001'
        if self.evidence_mode == 'revoked':
            liquidity['revoked'] = True
        return [liquidity, tier]

    def compiler(self):
        return AuthorityCompiler(
            mandate=self.mandate,
            permission_policy=self.policy,
            effect_semantics_resolver=self.semantics,
            state_resolver=self.state,
            evidence_resolver=self.evidence,
            compiler_id='settlement-authority-compiler',
            effect_resolver_id='settlement-semantics/v1',
            state_resolver_id='treasury-state/v1',
            evidence_resolver_id='settlement-evidence/v1',
        )

    def test_clean_proposal_compiles_to_nonexecuting_verified_commit_settings(self):
        result = self.compiler().compile(self.proposal, now=self.now)
        self.assertEqual(result['decision'], 'COMMIT_ELIGIBLE')
        self.assertEqual(result['execution_authority'], 'NONE_UNTIL_VERIFIED_COMMIT')
        self.assertEqual(result['commit_settings']['profile'], AUTHORITY_COMPILER_SETTINGS_PROFILE)
        self.assertGreater(result['max_authorization_ttl_seconds'], 0)
        self.assertLessEqual(result['max_authorization_ttl_seconds'], 30)
        self.assertEqual(validate_compiler_result(result), result)

    def test_mandate_limit_blocks_before_evidence_resolution(self):
        calls = []
        def evidence_should_not_run(*args):
            calls.append(True)
            return []
        compiler = AuthorityCompiler(
            mandate=self.mandate,
            permission_policy=self.policy,
            effect_semantics_resolver=self.semantics,
            state_resolver=self.state,
            evidence_resolver=evidence_should_not_run,
        )
        proposal = clone(self.proposal)
        proposal['settings']['amount_cents'] = 1_000_001
        result = compiler.compile(proposal, now=self.now)
        self.assertEqual(result['decision'], 'DENY')
        self.assertIn('mandate:payment_limit_exceeded', result['reason_codes'])
        self.assertEqual(calls, [])

    def test_unmandated_producer_is_denied(self):
        proposal = clone(self.proposal)
        proposal['producer_id'] = 'other-agent'
        result = self.compiler().compile(proposal, now=self.now)
        self.assertEqual(result['decision'], 'DENY')
        self.assertIn('proposal_producer_not_mandated', result['reason_codes'])

    def test_missing_evidence_quarantines(self):
        self.evidence_mode = 'missing'
        result = self.compiler().compile(self.proposal, now=self.now)
        self.assertEqual(result['decision'], 'QUARANTINE')
        self.assertTrue(any(reason.startswith('requirement_missing:') for reason in result['reason_codes']))
        self.assertIsNone(result['commit_settings'])

    def test_self_issued_evidence_denies(self):
        self.evidence_mode = 'self'
        result = self.compiler().compile(self.proposal, now=self.now)
        self.assertEqual(result['decision'], 'DENY')
        self.assertTrue(any('self_evidence_forbidden' in reason for reason in result['reason_codes']))

    def test_state_drift_denies(self):
        self.current_state = '99' * 32
        result = self.compiler().compile(self.proposal, now=self.now)
        self.assertEqual(result['decision'], 'DENY')
        self.assertIn('state_changed_since_proposal', result['reason_codes'])

    def test_advisory_and_model_changes_do_not_change_permission_decision(self):
        a = self.compiler().compile(self.proposal, now=self.now)
        b_proposal = clone(self.proposal)
        b_proposal['producer_model'] = 'optimizer-b'
        b_proposal['advisory_hash'] = 'bb' * 32
        b = self.compiler().compile(b_proposal, now=self.now)
        self.assertEqual(a['decision'], 'COMMIT_ELIGIBLE')
        self.assertEqual(b['decision'], 'COMMIT_ELIGIBLE')
        self.assertEqual(a['proposal_effect_hash'], b['proposal_effect_hash'])
        self.assertNotEqual(a['proposal_hash'], b['proposal_hash'])

    def test_preflight_blocks_after_compiler_window_expires(self):
        compiler = self.compiler()
        result = compiler.compile(self.proposal, now=self.now)
        preflight = compiler.preflight(
            result, self.proposal, now=self.now + timedelta(seconds=31)
        )
        self.assertFalse(preflight['allowed'])
        self.assertIn('compiler_authorization_window_expired', preflight['reason_codes'])

    def test_preflight_blocks_state_change_after_compile(self):
        compiler = self.compiler()
        result = compiler.compile(self.proposal, now=self.now)
        self.current_state = '44' * 32
        preflight = compiler.preflight(result, self.proposal, now=self.now + timedelta(seconds=1))
        self.assertFalse(preflight['allowed'])
        self.assertIn('state_changed_since_proposal', preflight['reason_codes'])

    def test_tampered_compiler_result_fails_closed(self):
        compiler = self.compiler()
        result = compiler.compile(self.proposal, now=self.now)
        tampered = clone(result)
        tampered['commit_settings']['effect_settings']['amount_cents'] = 1
        preflight = compiler.preflight(tampered, self.proposal, now=self.now)
        self.assertFalse(preflight['allowed'])
        self.assertTrue(any(reason.startswith('compiler_artifact_invalid:') for reason in preflight['reason_codes']))

    def test_execute_once_forces_receiver_owned_preflight(self):
        compiler = self.compiler()
        result = compiler.compile(self.proposal, now=self.now)
        ledger = FakeVerifiedCommitLedger()
        action = {
            'tool': self.proposal['tool'],
            'target': self.proposal['target'],
            'settings': result['commit_settings'],
            'run_id': 'run-001',
            'capsule_hash': '55' * 32,
            'evidence_hashes': ['66' * 32],
            'policy_hash': '77' * 32,
        }
        called = []
        execution = compiler.execute_once(
            ledger,
            {'signed': 'receipt'},
            action,
            self.proposal,
            result,
            one_use_code='88' * 32,
            trusted_gate_keys=['99' * 32],
            executor=lambda tool, target, settings: called.append((tool, target, settings)) or {'ok': True},
            now=self.now,
        )
        self.assertTrue(execution['authorized'])
        self.assertEqual(called, [('payments.authorize', 'vendor://acme', {'amount_cents': 500_000, 'timing': 'immediate'})])
        self.assertEqual(len(ledger.calls), 1)
        self.assertIn('preflight', ledger.calls[0])

    def test_execute_once_rejects_settings_not_compiled(self):
        compiler = self.compiler()
        result = compiler.compile(self.proposal, now=self.now)
        action = {
            'tool': self.proposal['tool'],
            'target': self.proposal['target'],
            'settings': {'profile': 'wrong'},
        }
        with self.assertRaisesRegex(AuthorityCompilerError, 'execution_settings_not_compiled'):
            compiler.execute_once(
                FakeVerifiedCommitLedger(), {}, action, self.proposal, result,
                one_use_code='88' * 32,
                trusted_gate_keys=['99' * 32],
                executor=lambda tool, target, settings: None,
                now=self.now,
            )


if __name__ == '__main__':
    unittest.main()
