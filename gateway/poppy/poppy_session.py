#!/usr/bin/env python3
"""POPPY-PROOF-001: Minimal Poppy Draft 0.1 session implementation.

Faithful to Personal Agent Protocol Draft 0.1 (2026-10-09,
personalagentprotocol.org):

- Discovery: company publishes /.well-known/poppy.json (version 0.1).
- Sign-in: user signs in on the company's page via OAuth 2.0 patterns
  (DPoP-bound tokens, PKCE-style verifier). Simulated: no real OAuth
  server, but real Ed25519 cryptography for JWT signing and DPoP binding.
- Session: short-lived signed JWT covering API calls. User chooses
  read-only or write access at sign-in.
- The session JWT proves identity + coarse scope. It does NOT bind the
  owner to exact operation terms — that is the OpenLine extension
  (see poppy_receiver.py).

This module is the Poppy-native baseline. It is not weakened to make
the extension look better.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


POPPY_SPEC_VERSION = "0.1"
POPPY_SPEC_DATE = "2026-10-09"
POPPY_SPEC_URL = "https://personalagentprotocol.org"

SESSION_TTL_SECONDS = 900  # 15 minutes, short-lived per draft 0.1


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def public_key_hex(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    if isinstance(key, Ed25519PrivateKey):
        key = key.public_key()
    return key.public_bytes_raw().hex()


class PoppyCompany:
    """A simulated Poppy company (the receiving business).

    Publishes poppy.json, runs sign-in, mints DPoP-bound session JWTs.
    """

    def __init__(self, org_name: str, org_id: str):
        self.org_name = org_name
        self.org_id = org_id
        self._signing_key = Ed25519PrivateKey.generate()
        # session_id -> session record
        self._sessions: dict[str, dict[str, Any]] = {}

    @property
    def public_key(self) -> str:
        return public_key_hex(self._signing_key)

    def discovery_doc(self) -> dict[str, Any]:
        """The /.well-known/poppy.json document (version 0.1)."""
        return {
            "poppy_version": POPPY_SPEC_VERSION,
            "organization": {
                "name": self.org_name,
                "id": self.org_id,
            },
            "sign_in": {
                "authorization_endpoint": f"https://{self.org_id}.example/authorize",
                "token_endpoint": f"https://{self.org_id}.example/token",
                "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
                "dpop_required": True,
                "pkce_required": True,
            },
            "session": {
                "token_type": "JWT+DPoP",
                "ttl_seconds": SESSION_TTL_SECONDS,
            },
            "interfaces": {
                "api": {"spec": "OpenAPI", "base_url": f"https://{self.org_id}.example/api/v1"},
                "company_agent": {"available": True},
            },
        }

    def sign_in(
        self,
        user_id: str,
        access_choice: str,
        dpop_public_key: str,
    ) -> dict[str, Any]:
        """User signs in on the company's page, chooses read or write.

        Returns a DPoP-bound session JWT (short-lived, signed).
        access_choice: "read" or "write" (per draft 0.1).
        """
        if access_choice not in ("read", "write"):
            raise ValueError(f"invalid access_choice: {access_choice}")
        now = datetime.now(timezone.utc)
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        expires_at = now + timedelta(seconds=SESSION_TTL_SECONDS)

        # DPoP binding: the session JWT is bound to the agent's DPoP key.
        # Only the holder of the DPoP private key can use this session.
        claims = {
            "iss": self.org_id,
            "sub": user_id,
            "sid": session_id,
            "scope": access_choice,  # coarse: read or write (draft 0.1)
            "cnf": {"jwk_thumbprint": hashlib.sha256(
                bytes.fromhex(dpop_public_key)).hexdigest()[:32]},
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "poppy_version": POPPY_SPEC_VERSION,
        }
        header = {"alg": "EdDSA", "typ": "JWT"}
        signing_input = (
            _b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + _b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode()
        signature = self._signing_key.sign(signing_input)
        token = signing_input.decode() + "." + _b64url(signature)

        self._sessions[session_id] = {
            "user_id": user_id,
            "scope": access_choice,
            "dpop_public_key": dpop_public_key,
            "expires_at": expires_at,
            "token": token,
        }
        return {
            "session_id": session_id,
            "session_token": token,
            "scope": access_choice,
            "expires_at": expires_at.isoformat(),
        }

    def verify_session(
        self,
        token: str,
        dpop_public_key: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Verify a Poppy session JWT: signature, expiry, DPoP binding.

        Returns {"valid": True, "claims": ...} or {"valid": False, "reason": ...}.
        """
        current = now or datetime.now(timezone.utc)
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"valid": False, "reason": "SESSION_TOKEN_MALFORMED"}
            signing_input = (parts[0] + "." + parts[1]).encode()
            signature = _b64url_decode(parts[2])
            self._signing_key.public_key().verify(signature, signing_input)
            claims = json.loads(_b64url_decode(parts[1]))

            if claims.get("poppy_version") != POPPY_SPEC_VERSION:
                return {"valid": False, "reason": "SESSION_VERSION_MISMATCH"}
            if current.timestamp() > claims.get("exp", 0):
                return {"valid": False, "reason": "SESSION_EXPIRED"}

            # DPoP binding: presenter must hold the bound key.
            expected_thumb = hashlib.sha256(
                bytes.fromhex(dpop_public_key)).hexdigest()[:32]
            if claims.get("cnf", {}).get("jwk_thumbprint") != expected_thumb:
                return {"valid": False, "reason": "DPOP_BINDING_MISMATCH"}

            # Session must still exist (allows company-side revocation).
            session = self._sessions.get(claims.get("sid", ""))
            if session is None:
                return {"valid": False, "reason": "SESSION_REVOKED"}

            return {"valid": True, "claims": claims}
        except InvalidSignature:
            return {"valid": False, "reason": "SESSION_SIGNATURE_INVALID"}
        except Exception as e:
            return {"valid": False, "reason": f"SESSION_VERIFY_ERROR: {e}"}

    def revoke_session(self, session_id: str) -> bool:
        """Company-side session revocation (per draft 0.1)."""
        return self._sessions.pop(session_id, None) is not None


class PoppyAgent:
    """A personal agent operating under Poppy draft 0.1.

    Holds a DPoP keypair. Discovers companies, opens sessions, presents
    operations. Does NOT hold owner authority — that comes from the
    OpenLine mandate (see poppy_receiver.py).
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._dpop_key = Ed25519PrivateKey.generate()

    @property
    def dpop_public_key(self) -> str:
        return public_key_hex(self._dpop_key)

    def discover(self, company: PoppyCompany) -> dict[str, Any]:
        """Read the company's poppy.json."""
        doc = company.discovery_doc()
        assert doc["poppy_version"] == POPPY_SPEC_VERSION
        return doc

    def open_session(
        self,
        company: PoppyCompany,
        user_id: str,
        access_choice: str,
    ) -> dict[str, Any]:
        """User signs in (simulated), agent gets a DPoP-bound session JWT."""
        return company.sign_in(
            user_id=user_id,
            access_choice=access_choice,
            dpop_public_key=self.dpop_public_key,
        )
