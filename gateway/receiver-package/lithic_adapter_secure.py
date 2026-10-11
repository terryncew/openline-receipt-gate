"""Compatibility import for the reviewed, packaged bounded-pilot adapter.

Ports durable pins, verified pending authorizations and signed decisions from
7a9d514 while replacing its revocation TODO, HMAC and transaction boundaries.
The old card+amount-only preauthorization API is intentionally superseded by
a separately signed, explicit payment intent. No Gateway files are replaced.
"""
from openline_receiver.lithic_adapter import (
    SecureLithicAdapter, create_payment_intent, payment_details,
    ReceiverStateError, ReceiptAccessError,
)

__all__ = ["SecureLithicAdapter", "create_payment_intent", "payment_details",
           "ReceiverStateError", "ReceiptAccessError"]
