"""COALITION-001: frozen mandate / credential / origin minting.

The origin identifier O is immutable and minted once. Actor authorities A and B
are distinct authority-bearing descendants of O: distinct actor ids, distinct
credentials, distinct secrets. A separate origin O2 with its own descendant
serves as the mandatory negative control.

Deterministic: no randomness anywhere. Lab credential secrets never leave the
apparatus and never appear in the observations record.
"""

import hashlib

FROZEN_NOW = 1_750_000_000  # frozen logical time; all minted authorizations expire after it

ORIGIN_O = "origin:coalition-001:O"
ORIGIN_O2 = "origin:coalition-001:O2"
BOUND = 100  # frozen cumulative bound B for both origins

_ORIGINS = {ORIGIN_O: BOUND, ORIGIN_O2: BOUND}

# Lab-only credential secrets. Held by the receiver's registry for signature
# verification; never written to observations.
_CREDENTIAL_SECRETS = {
    "cred-A": "lab-secret-cred-A-001",
    "cred-B": "lab-secret-cred-B-001",
    "cred-O2-1": "lab-secret-cred-O2-1-001",
}

# (actor_id, credential_id) -> (origin_id, scope). This registry is what makes
# A and B *valid descendants* of O rather than bare keyholders.
_DESCENDANTS = {
    ("actor-A", "cred-A"): (ORIGIN_O, frozenset({"compute.dispatch"})),
    ("actor-B", "cred-B"): (ORIGIN_O, frozenset({"compute.dispatch"})),
    ("actor-O2-1", "cred-O2-1"): (ORIGIN_O2, frozenset({"compute.dispatch"})),
}


def known_credential(cred_id):
    return cred_id in _CREDENTIAL_SECRETS


def credential_secret(cred_id):
    return _CREDENTIAL_SECRETS[cred_id]


def descendant_origin(actor_id, cred_id):
    return _DESCENDANTS[(actor_id, cred_id)][0]


def descendant_scope(actor_id, cred_id):
    return _DESCENDANTS[(actor_id, cred_id)][1]


def known_origin(origin_id):
    return origin_id in _ORIGINS


def origin_bound(origin_id):
    return _ORIGINS[origin_id]


def canonical_payload(auth):
    return "|".join([
        auth["origin_id"], auth["actor_id"], auth["credential_id"],
        str(auth["units"]), auth["action"], auth["nonce"],
        auth["intent_id"], str(auth["expires"]),
    ])


def sign(auth, secret):
    return hashlib.sha256((canonical_payload(auth) + "|" + secret).encode("utf-8")).hexdigest()


def mint_authorization(actor_id, credential_id, units, action, nonce, intent_id,
                      expires=FROZEN_NOW + 3600, origin_id=None):
    """Mint a signed authorization for a registered descendant authority."""
    if origin_id is None:
        origin_id = descendant_origin(actor_id, credential_id)
    auth = {
        "origin_id": origin_id,
        "actor_id": actor_id,
        "credential_id": credential_id,
        "units": units,
        "action": action,
        "nonce": nonce,
        "intent_id": intent_id,
        "expires": expires,
    }
    auth["signature"] = sign(auth, credential_secret(credential_id))
    return auth


def actor_credentials_distinct():
    """Observational check for the frozen actor condition: A and B hold
    distinct credentials and distinct actor identities."""
    return ("cred-A" != "cred-B"
            and "actor-A" != "actor-B"
            and _CREDENTIAL_SECRETS["cred-A"] != _CREDENTIAL_SECRETS["cred-B"]
            and descendant_origin("actor-A", "cred-A") == ORIGIN_O
            and descendant_origin("actor-B", "cred-B") == ORIGIN_O)
