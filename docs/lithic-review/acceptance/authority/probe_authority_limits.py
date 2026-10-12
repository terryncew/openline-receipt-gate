import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from pathlib import Path
import time
import unittest
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from openline_receiver.lithic_adapter import ACTION, create_payment_intent, payment_details
from openline_receiver.openline_wallet.crypto import public_key_hex
from openline_receiver.wallet_bridge import worker_present
from test_lithic_wallet_revocation import WalletRevocationTests

observations = []

class IndependentAuthorityProbes(WalletRevocationTests):
    def test_two_purchases_under_one_scope_grant(self):
        first, *_ = self._preauthorize()
        self.assertEqual(self.adapter.handle_asa(first), {'result': 'APPROVED'})
        second = self._request()
        second['merchant']['acceptor_id'] = 'SECOND-MERCHANT'
        second['merchant']['descriptor'] = 'SECOND OWNER UNSPECIFIED MERCHANT'
        self._preauthorize(request=second)
        self.assertEqual(self.adapter.handle_asa(second), {'result': 'APPROVED'})
        self.assertEqual(len(self.bundle['events']), 1)
        observations.append({'property': 'owner scope is repeatable; no aggregate $1 or exact-merchant owner cap',
                             'observed': 'two distinct $1 purchases at different merchants APPROVED under the same owner scope grant'})

    def test_matching_request_authenticated_before_intent(self):
        key = b'independent-authority-audit-key'
        self.adapter.sandbox = True
        self.adapter.signing_secrets = ('whsec_' + base64.b64encode(key).decode(),)
        request = self._request(created=(datetime.now(timezone.utc) - timedelta(seconds=120)).isoformat())
        body = json.dumps(request, separators=(',', ':')).encode()
        msg_id = str(uuid.uuid4())
        stamp = str(int(time.time()) - 120)
        sig = base64.b64encode(hmac.new(key, msg_id.encode() + b'.' + stamp.encode() + b'.' + body, hashlib.sha256).digest()).decode()
        headers = {'webhook-id': msg_id, 'webhook-timestamp': stamp, 'webhook-signature': 'v1,' + sig}
        self._preauthorize()
        self.assertEqual(self.adapter.handle_asa(headers=headers, raw_body=body), {'result': 'APPROVED'})
        observations.append({'property': 'first-match covers previously initiated/unseen ASA as well as newly initiated purchases',
                             'observed': 'matching purchase created and authenticated 120 seconds before the intent was APPROVED when first delivered after preauthorization'})

    def test_unintended_matching_token_consumes_intent(self):
        intended, *_ = self._preauthorize()
        unintended = copy.deepcopy(intended)
        unintended['token'] = str(uuid.uuid4())
        self.assertEqual(self.adapter.handle_asa(unintended), {'result': 'APPROVED'})
        self.assertEqual(self.adapter.handle_asa(intended), {'result': 'CARD_PAUSED'})
        observations.append({'property': 'no exact transaction/order binding before ASA',
                             'observed': 'different token with identical details APPROVED; intended token then CARD_PAUSED'})

    def test_signed_but_undelivered_revocation_does_not_take_effect(self):
        request, *_ = self._preauthorize()
        self.owner.revoke(self.mandate)
        self.owner.export_bundle()
        self.assertEqual(self.adapter.handle_asa(request), {'result': 'APPROVED'})
        observations.append({'property': 'revocation boundary is receiver admission, not owner signing',
                             'observed': 'signed but undelivered owner revocation did not stop pending APPROVED decision'})

    def test_arbitrary_worker_cannot_preauthorize(self):
        foreign = Ed25519PrivateKey.generate()
        _, _, _, result = self._preauthorize(worker=foreign, expected=False)
        self.assertEqual(result['reason'], 'SIGNED_INTENT_INVALID')
        self.assertEqual(self.adapter.db.execute('SELECT count(*) FROM pending').fetchone()[0], 0)
        observations.append({'property': 'cryptographic independence from worker assertion',
                             'observed': 'foreign key claiming legitimate mandate refused before pending permission'})

    def test_successor_requires_new_key_presentation_and_binding(self):
        self._revoke()
        successor = Ed25519PrivateKey.generate()
        subject = 'successor-independent-audit'
        grant = self.owner.grant(subject_id=subject, subject_public_key=public_key_hex(successor),
                                scopes=[ACTION], expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        bundle = self.owner.export_bundle()
        mandate = grant['data']['mandate_id']
        self.adapter.admit_bundle(self.principal, bundle)
        self.adapter.bind_card(self.card, self.principal, mandate, subject)
        request, _, _, bad = self._preauthorize(bundle=bundle, worker=self.worker, mandate=mandate, subject=subject, expected=False)
        self.assertEqual(bad['reason'], 'SIGNED_INTENT_INVALID')
        self._preauthorize(bundle=bundle, worker=successor, mandate=mandate, subject=subject, request=request)
        self.assertEqual(self.adapter.handle_asa(request), {'result': 'APPROVED'})
        observations.append({'property': 'old worker cannot use successor mandate',
                             'observed': 'old key refused on rebound successor authority; successor key APPROVED'})

names = [n for n in IndependentAuthorityProbes.__dict__ if n.startswith('test_')]
suite = unittest.TestSuite(IndependentAuthorityProbes(n) for n in names)
result = unittest.TextTestRunner(verbosity=2).run(suite)
Path('authority-probe-result.json').write_text(json.dumps({'passed': result.testsRun - len(result.failures) - len(result.errors),
                                                      'failures': len(result.failures), 'errors': len(result.errors),
                                                      'observations': observations}, indent=2) + '\n')
raise SystemExit(0 if result.wasSuccessful() else 1)
