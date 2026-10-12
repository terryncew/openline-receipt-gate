"""Live database corruption must not be concealed by SQLite's open page cache.

These use the real authenticated loopback ASA handler and signed Wallet setup.
Mutation is deliberate fault injection into temporary test state, never a
receiver recovery mechanism. Each test retains the open adapter connection.
"""
from __future__ import annotations

import os
import unittest

import test_lithic_preflight as fixture


class LiveStateTests(unittest.TestCase):
    def setUp(self):
        # Compose the shared real-Wallet HTTP fixture without inheriting its
        # tests (which would otherwise run the entire suite a second time).
        self.pilot = fixture.HTTPPreflightTests(
            methodName="test_card_binding_and_missing_authentication_never_approve")
        self.pilot.setUp()
        self.addCleanup(self.pilot.doCleanups)
        self.pilot.authorize()

    def _checkpoint(self):
        row = self.pilot.adapter.db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertEqual(row[0], 0, "Fault injection requires a completed checkpoint")
        self.assertGreaterEqual(self.pilot.db_path.stat().st_size, 4096)

    def _replace(self, contents):
        prior = self.pilot.db_path.stat()
        replacement = self.pilot.path / "replacement.sqlite3"
        replacement.write_bytes(contents)
        os.replace(replacement, self.pilot.db_path)
        self.assertNotEqual(prior.st_ino, self.pilot.db_path.stat().st_ino)

    def _overwrite(self, contents, *, truncate=False, offset=0):
        prior = self.pilot.db_path.stat()
        with self.pilot.db_path.open("wb" if truncate else "r+b") as state:
            state.seek(offset)
            state.write(contents)
            state.flush()
            os.fsync(state.fileno())
        self.assertEqual(prior.st_ino, self.pilot.db_path.stat().st_ino)

    def _assert_unacknowledged(self):
        status, result, elapsed = self.pilot.asa()
        self.assertEqual((status, result), (503, None))
        self.assertLess(elapsed, 6)
        # Inspect the original still-open connection. Nothing may commit on
        # that orphaned/cached state merely because a receipt could be signed.
        self.assertEqual(self.pilot.adapter.db.execute(
            "SELECT count(*) FROM decisions").fetchone()[0], 0)
        self.assertEqual(self.pilot.adapter.db.execute(
            "SELECT count(*) FROM pending").fetchone()[0], 1)

    def test_open_database_replaced_by_corrupt_file_does_not_acknowledge_approval(self):
        self._checkpoint()
        self._replace(b"CORRUPT STATE")
        self._assert_unacknowledged()

    def test_open_database_replaced_by_empty_file_does_not_acknowledge_approval(self):
        self._checkpoint()
        self._replace(b"")
        self._assert_unacknowledged()

    def test_same_inode_header_corruption_does_not_acknowledge_approval(self):
        self._checkpoint()
        self._overwrite(b"CORRUPT STATE    ")
        self._assert_unacknowledged()

    def test_same_inode_main_file_truncation_does_not_acknowledge_approval(self):
        self._checkpoint()
        self._overwrite(b"CORRUPT STATE", truncate=True)
        self._assert_unacknowledged()

    def test_main_btree_corruption_with_valid_file_header_fails_closed(self):
        self._checkpoint()
        page_size = self.pilot.adapter.db.execute("PRAGMA page_size").fetchone()[0]
        metadata_page = self.pilot.adapter.db.execute(
            "SELECT rootpage FROM sqlite_master WHERE name='metadata'").fetchone()[0]
        # Damage an existing B-tree page, leaving file identity, size and the
        # SQLite header intact. A fresh reader must detect the corrupt page.
        self._overwrite(b"\x7f", offset=(metadata_page - 1) * page_size)
        self.assertEqual(self.pilot.db_path.read_bytes()[:16], b"SQLite format 3\x00")
        self._assert_unacknowledged()

    def test_file_replacement_during_signing_rolls_back_before_commit(self):
        self._checkpoint()
        signer = self.pilot.adapter._sign_receipt

        def replace_while_signing(body):
            signed = signer(body)
            self._replace(b"CORRUPT STATE")
            return signed

        self.pilot.adapter._sign_receipt = replace_while_signing
        self._assert_unacknowledged()

    def test_committed_approval_retry_fails_when_live_state_file_is_replaced(self):
        self.assertEqual(self.pilot.asa()[:2], (200, {"result": "APPROVED"}))
        self._checkpoint()
        self._replace(b"CORRUPT STATE")
        status, result, elapsed = self.pilot.asa()
        self.assertEqual((status, result), (503, None))
        self.assertLess(elapsed, 6)
        self.assertEqual(self.pilot.adapter.db.execute(
            "SELECT count(*) FROM decisions").fetchone()[0], 1)

    def test_authenticated_receipt_read_refuses_replaced_live_database(self):
        self.assertEqual(self.pilot.asa()[:2], (200, {"result": "APPROVED"}))
        self.assertEqual(self.pilot.receipt()[0], 200)
        self._checkpoint()
        self._replace(b"CORRUPT STATE")
        status, result, elapsed = self.pilot.receipt()
        self.assertEqual((status, result), (503, None))
        self.assertLess(elapsed, 6)

if __name__ == "__main__":
    unittest.main(verbosity=2)
