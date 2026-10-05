"""Security controls for the apparatus; no scenario arm is executed here."""
import time
import unittest
from unittest.mock import patch

from protocol import *
from service import Authority, ReceiverService
from verify import verify_arm


class ProtocolSecurity(unittest.TestCase):
    def setUp(self):
        self.owner = Ed25519PrivateKey.generate()
        self.server = Ed25519PrivateKey.generate()
        self.a = Ed25519PrivateKey.generate()
        self.b = Ed25519PrivateKey.generate()
        from olp_gate.crypto import public_key_hex
        self.root = public_key_hex(self.owner)
        self.a_pub, self.b_pub = public_key_hex(self.a), public_key_hex(self.b)
        self.contract = {'owner_key': self.root, 'as_key': public_key_hex(self.server),
                         'workers': {'A': self.a_pub, 'B': self.b_pub}}
        self.grant = issue(self.owner, OWNER, OWNER, RECEIVER, 'at+jwt',
            {'job_id': JOB, 'scope': 'refund', 'client_id': 'job-client', 'max_amount_cents': 100})
        self.contract['grant_hash'] = digest(self.grant)
        self.claims = jwt.decode(self.grant, options={'verify_signature': False})

    def check_grant(self, token):
        with self.assertRaises((jwt.PyJWTError, ValueError)):
            grant_claims(token, self.contract)

    def test_signature_tamper_rejected(self):
        parts = self.grant.split('.')
        sig = jwt.utils.base64url_decode(parts[2])
        parts[2] = jwt.utils.base64url_encode(bytes([sig[0] ^ 1]) + sig[1:]).decode()
        self.check_grant('.'.join(parts))

    def test_untrusted_signer_rejected(self):
        self.check_grant(jwt.encode(self.claims, self.b, algorithm='EdDSA', headers={'typ': 'at+jwt'}))

    def test_wrong_issuer_and_audience_rejected(self):
        for field, value in [('iss', 'attacker'), ('aud', 'other-receiver')]:
            with self.subTest(field=field):
                claims = dict(self.claims, **{field: value})
                self.check_grant(jwt.encode(claims, self.owner, algorithm='EdDSA', headers={'typ': 'at+jwt'}))

    def test_missing_required_claim_rejected(self):
        for field in REQUIRED + ['scope', 'client_id', 'job_id']:
            with self.subTest(field=field):
                claims = dict(self.claims)
                del claims[field]
                self.check_grant(jwt.encode(claims, self.owner, algorithm='EdDSA', headers={'typ': 'at+jwt'}))

    def test_algorithm_and_type_confusion_rejected(self):
        self.check_grant(jwt.encode(self.claims, 'irrelevant-test-string-at-least-32-bytes', algorithm='HS256', headers={'typ': 'at+jwt'}))
        self.check_grant(jwt.encode(self.claims, self.owner, algorithm='EdDSA', headers={'typ': 'JWT'}))

    def test_exact_expiry_with_zero_leeway(self):
        self.assertTrue(evaluate_standard('JWT_OFFLINE', self.grant, 'B', 25, None,
                                          self.contract, at=self.claims['exp'] - .001)[0])
        self.assertEqual(evaluate_standard('JWT_OFFLINE', self.grant, 'B', 25, None,
                                          self.contract, at=self.claims['exp'])[1], 'expired_token_or_status')

    def test_mutated_job_and_escalated_scope_rejected(self):
        for field, value in [('job_id', 'other-job'), ('scope', 'refund admin')]:
            with self.subTest(field=field):
                token = jwt.encode(dict(self.claims, **{field: value}), self.owner,
                                   algorithm='EdDSA', headers={'typ': 'at+jwt'})
                self.check_grant(token)

    def test_amount_cap_enforced(self):
        self.assertEqual(evaluate_standard('JWT_OFFLINE', self.grant, 'B', 101, None,
                                          self.contract)[1], 'amount_out_of_scope')

    def test_holder_binding_is_not_bearer_succession(self):
        grant = jwt.encode(dict(self.claims, cnf={'jwk': jwk(self.a_pub)}), self.owner,
                           algorithm='EdDSA', headers={'typ': 'at+jwt'})
        status = self.status([])
        self.assertTrue(evaluate_standard('JWT_BOUND', grant, 'A', 25, status, self.contract)[0])
        self.assertEqual(evaluate_standard('JWT_BOUND', grant, 'B', 25, status, self.contract)[1], 'holder_mismatch')

    def status(self, revoked, **kw):
        return issue(self.owner, OWNER, RECEIVER, RECEIVER, 'revocation-list+jwt',
                      {'sequence': 1, 'job_id': JOB, 'revoked': revoked, **kw}, ttl=1)

    def test_revocation_and_stale_list_fail_closed(self):
        self.assertEqual(evaluate_standard('OWNER_LIST', self.grant, 'B', 25,
            self.status([self.claims['jti']]), self.contract)[1], 'owner_revoked_jti')
        stale = self.status([], exp=int(time.time()) - 1)
        self.assertFalse(evaluate_standard('OWNER_LIST', self.grant, 'B', 25, stale, self.contract)[0])

    def test_receiver_rejects_list_rollback(self):
        config = {'arm': 'OWNER_LIST', 'contract': self.contract, 'owner_key': self.root,
                  'authority_url': 'http://127.0.0.1:1'}
        receiver = ReceiverService(config)
        receiver.list_sequence = 2
        with patch('service.request', return_value=(200, {'snapshot': self.status([])})):
            with self.assertRaisesRegex(ValueError, 'list_rollback'):
                receiver.refresh({})

    def exchange_config(self):
        from cryptography.hazmat.primitives import serialization
        return {'contract': self.contract, 'token_endpoint': 'http://127.0.0.1:1/exchange',
                'as_private': self.server.private_bytes(serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()}

    def exchange_form(self, **kw):
        cfg = self.exchange_config()
        return {'grant_type': EXCHANGE, 'subject_token_type': JWT_TYPE,
                'requested_token_type': TOKEN_TYPE, 'subject_token': self.grant,
                'audience': RECEIVER, 'scope': 'refund', 'client_id': 'B',
                'client_assertion_type': ASSERTION,
                'client_assertion': issue(self.b, 'B', 'B', cfg['token_endpoint'], 'JWT', ttl=5), **kw}

    def test_exchange_valid_response_and_assertion_replay(self):
        cfg, form, replay = self.exchange_config(), self.exchange_form(), set()
        output = exchange(form, cfg, replay)
        self.assertEqual(output['issued_token_type'], TOKEN_TYPE)
        self.assertEqual(output['token_type'], 'Bearer')
        token = grant_claims(output['access_token'], self.contract, exchanged=True)
        self.assertEqual(token['act'], {'sub': 'B'})
        self.assertEqual(token['exp'], self.claims['exp'])
        with self.assertRaisesRegex(ValueError, 'client_assertion_replay'):
            exchange(form, cfg, replay)

    def test_exchange_rejects_scope_target_revoked_grant_and_wrong_client(self):
        for override, reason in [({'scope': 'admin'}, 'invalid_scope'),
                                 ({'audience': 'elsewhere'}, 'invalid_target'),
                                 ({'client_id': 'unknown'}, 'invalid_client')]:
            with self.subTest(override=override):
                with self.assertRaisesRegex(ValueError, reason):
                    exchange(self.exchange_form(**override), self.exchange_config(), set())
        with self.assertRaisesRegex(ValueError, 'invalid_grant_revoked'):
            exchange(self.exchange_form(), dict(self.exchange_config(), revoked=True), set())

    def test_wrong_owner_cannot_revoke(self):
        authority = Authority({'arm': 'OWNER_LIST', 'owner_key': self.root,
                               'contract': self.contract})
        forged = issue(self.b, OWNER, OWNER, RECEIVER, 'owner-revocation+jwt',
                       {'job_id': JOB, 'grant_hash': self.contract['grant_hash']})
        with self.assertRaises(jwt.InvalidSignatureError):
            authority.handle('/revoke', {'owner_request': forged})
        self.assertFalse(authority.revoked)

    def test_signed_introspection_binds_exact_token_and_revocation(self):
        output = exchange(self.exchange_form(), self.exchange_config(), set())
        access = output['access_token']

        def introspection(active, token_hash):
            return issue(self.server, AS, RECEIVER, RECEIVER, 'token-introspection+jwt',
                {'token_hash': token_hash, 'token_introspection': {
                    'active': active, 'sub': OWNER, 'job_id': JOB}}, ttl=1)

        self.assertTrue(evaluate_standard('OAUTH_EXCHANGE', access, 'B', 25,
            introspection(True, digest(access)), self.contract)[0])
        self.assertEqual(evaluate_standard('OAUTH_EXCHANGE', access, 'B', 25,
            introspection(False, digest(access)), self.contract)[1], 'revoked_at_as')
        self.assertEqual(evaluate_standard('OAUTH_EXCHANGE', access, 'B', 25,
            introspection(True, digest('another-token')), self.contract)[1], 'introspection_token_mismatch')


if __name__ == '__main__':
    unittest.main(verbosity=2)
