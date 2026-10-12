"""ASA HMAC rejection tests and independently checked official SDK fixtures.

The two OfficialLithicVerifierTests require lithic[webhooks] v0.132.0; set
OPENLINE_REQUIRE_OFFICIAL_LITHIC=1 to make a missing SDK a failure. The published
SDK vector is a general webhook signing vector, not an ASA payload example.
"""

import base64
import hashlib
import hmac
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from openline_receiver.lithic_hmac import (
    LithicAuthenticationError,
    decode_asa_secret,
    verify_lithic_hmac,
)


NOW = 1_700_000_000
KEY = bytes(range(32))
NEW_KEY = bytes(range(32, 64))
SECRET = "whsec_" + base64.b64encode(KEY).decode("ascii")
NEW_SECRET = "whsec_" + base64.b64encode(NEW_KEY).decode("ascii")
# Complete synthetic ASA fixture independently checked against Lithic's pinned
# official OpenAPI schema. Keep the original bytes (including indentation).
# The signer below never uses the implementation under test.
BODY_PATH = Path(__file__).with_name("fixtures") / "official-asa-request.json"
BODY = BODY_PATH.read_bytes()


def independent_headers(body=BODY, key=KEY, timestamp=NOW, message_id="msg_independent_asa"):
    signing_input = f"{message_id}.{timestamp}.".encode("ascii") + body
    signature = base64.b64encode(hmac.new(key, signing_input, hashlib.sha256).digest()).decode("ascii")
    return {
        "webhook-id": message_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": "v1," + signature,
    }


# Copied verbatim from official SDK v0.132.0 tests/api_resources/test_webhooks.py
# at a1e8c1861ecb7053ef97aad80dcb48aa8fda8b3f; independent published signature.
PUBLISHED_BODY = b'{"card_token":"sit Lorem ipsum, accusantium repellendus possimus","created_at":"elit. placeat libero architecto molestias, sit","account_token":"elit.","issuer_decision":"magnam, libero esse Lorem ipsum magnam, magnam,","tokenization_attempt_id":"illum dolor repellendus libero esse accusantium","wallet_decisioning_info":{"device_score":"placeat architecto"},"digital_wallet_token_metadata":{"status":"reprehenderit dolor","token_requestor_id":"possimus","payment_account_info":{"account_holder_data":{"phone_number":"libero","email_address":"nobis molestias, veniam culpa! quas elit. quas libero esse architecto placeat"},"pan_unique_reference":"adipisicing odit magnam, odit"}}}'
PUBLISHED_SECRET = "whsec_zlFsbBZ8Xcodlpcu6NDTdSzZRLSdhkst"
PUBLISHED_NOW = 1_676_312_382
PUBLISHED_HEADERS = {
    "webhook-id": "msg_2Lh9KRb0pzN4LePd3XiA4v12Axj",
    "webhook-timestamp": str(PUBLISHED_NOW),
    "webhook-signature": "v1,Dwa0AHInLL3XFo2sxcHamOQDrJNi7F654S3L6skMAOI=",
}


class LithicHMACTests(unittest.TestCase):
    def verify(self, body=BODY, headers=None, secrets=SECRET, now=NOW):
        return verify_lithic_hmac(body, independent_headers() if headers is None else headers, secrets, now=now)

    def test_valid_original_bytes_case_insensitive_headers(self):
        headers = {key.upper(): value for key, value in independent_headers().items()}
        self.assertIsNone(self.verify(headers=headers))

    def test_published_sdk_vector(self):
        self.assertIsNone(self.verify(PUBLISHED_BODY, PUBLISHED_HEADERS, PUBLISHED_SECRET, PUBLISHED_NOW))

    def test_secret_is_base64_decoded_not_ascii_encoded(self):
        self.assertEqual(decode_asa_secret(SECRET), KEY)
        self.assertEqual(decode_asa_secret(SECRET.removeprefix("whsec_").rstrip("=")), KEY)
        with self.assertRaises(LithicAuthenticationError):
            self.verify(headers=independent_headers(key=SECRET.encode()))

    def test_tampered_body_and_reserialized_json_decline(self):
        import json
        for changed in [BODY.replace(b'100', b'101'), json.dumps(json.loads(BODY), separators=(",", ":")).encode()]:
            with self.subTest(body=changed), self.assertRaises(LithicAuthenticationError):
                self.verify(body=changed)

    def test_wrong_secret_and_invalid_signatures_decline(self):
        with self.assertRaises(LithicAuthenticationError):
            self.verify(secrets=NEW_SECRET)
        for signature in ["v1,AAAA", "v1,%%%", "v2," + independent_headers()["webhook-signature"][3:], "unversioned"]:
            with self.subTest(signature=signature), self.assertRaises(LithicAuthenticationError):
                self.verify(headers={**independent_headers(), "webhook-signature": signature})

    def test_old_and_future_timestamps_decline(self):
        for timestamp in [NOW - 301, NOW + 301]:
            with self.subTest(timestamp=timestamp), self.assertRaises(LithicAuthenticationError):
                self.verify(headers=independent_headers(timestamp=timestamp))

    def test_missing_headers_decline(self):
        for name in independent_headers():
            headers = independent_headers()
            del headers[name]
            with self.subTest(name=name), self.assertRaises(LithicAuthenticationError):
                self.verify(headers=headers)

    def test_multiple_signatures_and_explicit_rotation_keys(self):
        old = independent_headers()
        new = independent_headers(key=NEW_KEY)
        rotation = {**old, "webhook-signature": "v1,AAAA " + new["webhook-signature"] + " " + old["webhook-signature"]}
        self.assertIsNone(self.verify(headers=rotation, secrets=SECRET))
        self.assertIsNone(self.verify(headers=rotation, secrets=NEW_SECRET))
        self.assertIsNone(self.verify(headers=new, secrets=(SECRET, NEW_SECRET)))
        with self.assertRaises(LithicAuthenticationError):
            self.verify(headers=old, secrets=(NEW_SECRET,))

    def test_missing_invalid_configuration_and_duplicate_headers_decline(self):
        for secrets in [None, (), "", "whsec_", "not a base64 secret", b"raw-key"]:
            with self.subTest(secrets=secrets), self.assertRaises(LithicAuthenticationError):
                self.verify(secrets=secrets)
        with self.assertRaises(LithicAuthenticationError):
            self.verify(headers={**independent_headers(), "Webhook-ID": "different"})
        for timestamp in ["1700000000.0", "1.7e9", "01700000000", "-1"]:
            with self.subTest(timestamp=timestamp), self.assertRaises(LithicAuthenticationError):
                self.verify(headers={**independent_headers(), "webhook-timestamp": timestamp})

    def test_original_bytes_are_required_and_window_cannot_be_extended(self):
        with self.assertRaises(LithicAuthenticationError):
            self.verify(body=BODY.decode())
        with self.assertRaises(LithicAuthenticationError):
            verify_lithic_hmac(BODY, independent_headers(), SECRET, now=NOW, tolerance_seconds=301)


class OfficialLithicVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import lithic
            import standardwebhooks
        except ImportError as exc:
            if os.environ.get("OPENLINE_REQUIRE_OFFICIAL_LITHIC") == "1":
                raise RuntimeError("Pinned official Lithic SDK is required for this verification") from exc
            raise unittest.SkipTest("Install pinned lithic[webhooks] for official verifier checks") from exc
        if lithic.__version__ != "0.132.0":
            raise RuntimeError("Official verifier checks require Lithic SDK v0.132.0")
        cls.client = lithic.Lithic(api_key="offline-fixture-never-sent")
        cls.verification_error = standardwebhooks.WebhookVerificationError

    @classmethod
    def tearDownClass(cls):
        cls.client.close()

    def official_verify(self, body, headers, secret, now):
        class FixtureClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime.fromtimestamp(now, tz=tz or timezone.utc)
        # Only freeze the verifier clock; signatures are supplied independently.
        with patch("standardwebhooks.webhooks.datetime", FixtureClock):
            return self.client.webhooks.verify_signature(body, headers=headers, secret=secret)

    def test_published_signature_reproduced_by_official_sdk(self):
        self.assertIsNone(self.official_verify(PUBLISHED_BODY, PUBLISHED_HEADERS, PUBLISHED_SECRET, PUBLISHED_NOW))
        verify_lithic_hmac(PUBLISHED_BODY, PUBLISHED_HEADERS, PUBLISHED_SECRET, now=PUBLISHED_NOW)

    def test_official_verifier_against_independent_asa_fixtures(self):
        valid = independent_headers()
        rotated = {**valid, "webhook-signature": "v1,AAAA " + independent_headers(key=NEW_KEY)["webhook-signature"] + " " + valid["webhook-signature"]}
        for headers, secret in [(valid, SECRET), (rotated, SECRET), (rotated, NEW_SECRET)]:
            with self.subTest(secret=secret):
                self.assertIsNone(self.official_verify(BODY, headers, secret, NOW))
                verify_lithic_hmac(BODY, headers, secret, now=NOW)
        invalid_cases = [
            (BODY.replace(b'100', b'101'), valid, SECRET),
            (BODY, valid, NEW_SECRET),
            (BODY, {**valid, "webhook-signature": "v1,AAAA"}, SECRET),
            (BODY, independent_headers(timestamp=NOW - 301), SECRET),
            (BODY, independent_headers(timestamp=NOW + 301), SECRET),
        ]
        for body, headers, secret in invalid_cases:
            with self.subTest(headers=headers), self.assertRaises(self.verification_error):
                self.official_verify(body, headers, secret, NOW)
            with self.assertRaises(LithicAuthenticationError):
                verify_lithic_hmac(body, headers, secret, now=NOW)
        for name in valid:
            headers = {key: value for key, value in valid.items() if key != name}
            with self.subTest(missing=name), self.assertRaises(ValueError):
                self.official_verify(BODY, headers, SECRET, NOW)
            with self.assertRaises(LithicAuthenticationError):
                verify_lithic_hmac(BODY, headers, SECRET, now=NOW)


if __name__ == "__main__":
    unittest.main(verbosity=2)
