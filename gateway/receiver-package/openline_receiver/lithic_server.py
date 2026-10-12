"""Loopback-only ASA and authenticated read-only receipt endpoint for preflight."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sqlite3
from urllib.parse import unquote, urlsplit

from .lithic_adapter import ReceiptAccessError, ReceiverStateError
from .lithic_hmac import LithicAuthenticationError


class PilotHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, adapter):
        if address[0] not in {"127.0.0.1", "localhost"}:
            raise ValueError("Preflight server is restricted to loopback")
        if not adapter.sandbox or not adapter.signing_secrets:
            raise ValueError("Pilot HTTP requires configured sandbox authentication")
        self.adapter = adapter
        super().__init__(address, PilotHandler)


class PilotHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log authentication headers, raw requests or receipts.

    def _send(self, status, payload=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlsplit(self.path).path != "/asa":
            return self._send(404)
        for name in ("webhook-id", "webhook-timestamp", "webhook-signature"):
            # HTTPMessage.get()/dict conversion discards duplicate values.
            if len(self.headers.get_all(name, [])) != 1:
                return self._send(401)
        if self.headers.get("Transfer-Encoding") is not None:
            return self._send(400)
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                return self._send(400)
            length = int(lengths[0])
            if not 0 < length <= 65536:
                return self._send(413)
            self.connection.settimeout(2)
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self._send(400)
            result = self.server.adapter.handle_asa(headers=dict(self.headers), raw_body=raw)
        except LithicAuthenticationError:
            return self._send(401)
        except (ValueError, TypeError, KeyError, UnicodeError):
            return self._send(400)
        except (ReceiverStateError, sqlite3.Error, OSError):
            return self._send(503)
        return self._send(200, result)

    def do_GET(self):
        path = urlsplit(self.path).path
        if not path.startswith("/receipts/") or not path[len("/receipts/"):]:
            return self._send(404)
        authorization = self.headers.get_all("Authorization", [])
        if len(authorization) != 1 or not authorization[0].startswith("Bearer "):
            return self._send(401)
        try:
            receipt = self.server.adapter.retrieve_receipt(
                unquote(path[len("/receipts/"):]), authorization[0][7:])
        except ReceiptAccessError:
            return self._send(401)
        except (ValueError, TypeError):
            return self._send(404)
        except (ReceiverStateError, sqlite3.Error, OSError):
            return self._send(503)
        return self._send(200, receipt)

    def do_PUT(self):
        self._send(405)

    do_DELETE = do_PUT
    do_PATCH = do_PUT
