from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from pathlib import Path

from server.tgame_ticket_state import (
    delete_session,
    get_unexpired_session_uins,
    get_sessions_for_ip,
    get_ticket_crypto,
    issue_ticket,
    save_transport_key,
    touch_session,
)


class TGameTicketStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory(prefix="af-tgame-session-")
        root = Path(self.temp_dir.name)
        self.db_path = root / "accounts.sqlite3"
        self.private_key_path = root / "PRIVATE.PEM"
        # Session-store encryption derives from the stable server key material.
        self.private_key_path.write_bytes(b"test-only-private-key-material-" * 8)
        self.uin = 10001
        self.client_ip = "203.0.113.20"
        self.auth_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
        self.transport_key = b"LOCAL_GAME_KEY01"
        self.ticket = issue_ticket(
            self.uin,
            self.client_ip,
            self.auth_key,
            mode=3,
            ttl_seconds=120,
            session_ttl_seconds=120,
            db_path=self.db_path,
            private_key_path=self.private_key_path,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _kwargs(self) -> dict[str, Path]:
        return {
            "db_path": self.db_path,
            "private_key_path": self.private_key_path,
        }

    def test_ticket_recovers_the_auth_key_and_mode_from_sqlite(self) -> None:
        # A fresh lookup has no process-local cache to fall back to.
        result = get_ticket_crypto(
            self.ticket,
            self.uin,
            self.client_ip,
            **self._kwargs(),
        )
        self.assertEqual(len(self.ticket), 16)
        self.assertEqual(result["session_key"], self.auth_key)
        self.assertEqual(result["mode"], 3)
        self.assertEqual(result["uin"], self.uin)
        self.assertGreater(result["expires_at"], time.time())

    def test_crypto_keys_are_encrypted_at_rest(self) -> None:
        connection = sqlite3.connect(self.db_path)
        try:
            row = connection.execute(
                "SELECT auth_key_enc FROM af_tgame_sessions WHERE ticket = ?",
                (self.ticket.decode("ascii"),),
            ).fetchone()
        finally:
            connection.close()
        self.assertIsNotNone(row)
        self.assertNotIn(self.auth_key, bytes(row[0]))

    def test_transport_session_survives_reopen_and_is_bound_to_ip(self) -> None:
        saved = save_transport_key(
            self.ticket,
            self.uin,
            self.client_ip,
            self.transport_key,
            mode=3,
            ttl_seconds=120,
            **self._kwargs(),
        )
        self.assertTrue(saved)

        # get_sessions_for_ip performs a new SQLite read and decrypts the
        # persisted state, which is the same path used after process restart.
        sessions = get_sessions_for_ip(self.client_ip, **self._kwargs())
        self.assertEqual(len(sessions), 1)
        self.assertEqual(sessions[0]["uin"], self.uin)
        self.assertEqual(sessions[0]["transport_key"], self.transport_key)
        self.assertNotIn("auth_key", sessions[0])
        self.assertEqual(sessions[0]["state"], "transport_ready")
        self.assertEqual(get_sessions_for_ip("203.0.113.21", **self._kwargs()), [])

    def test_ticket_lookup_is_bound_to_uin_and_client_ip(self) -> None:
        self.assertIsNone(
            get_ticket_crypto(
                self.ticket,
                self.uin + 1,
                self.client_ip,
                **self._kwargs(),
            )
        )
        self.assertIsNone(
            get_ticket_crypto(
                self.ticket,
                self.uin,
                "203.0.113.21",
                **self._kwargs(),
            )
        )

    def test_auth_ticket_expiry_does_not_extend_with_game_session_ttl(self) -> None:
        short_ticket = issue_ticket(
            self.uin + 1,
            self.client_ip,
            self.auth_key,
            ttl_seconds=0.01,
            session_ttl_seconds=120,
            db_path=self.db_path,
            private_key_path=self.private_key_path,
        )
        time.sleep(0.02)
        self.assertIsNone(
            get_ticket_crypto(
                short_ticket,
                self.uin + 1,
                self.client_ip,
                **self._kwargs(),
            )
        )

    def test_idle_game_session_expiry_and_touch(self) -> None:
        now = time.time() + 5.0
        with patch("server.tgame_ticket_state.time.time") as clock:
            clock.return_value = now
            self.assertTrue(
                save_transport_key(
                    self.ticket,
                    self.uin,
                    self.client_ip,
                    self.transport_key,
                    ttl_seconds=0.03,
                    **self._kwargs(),
                )
            )
            clock.return_value = now + 0.01
            self.assertTrue(
                touch_session(
                    self.ticket,
                    self.uin,
                    self.client_ip,
                    ttl_seconds=0.08,
                    db_path=self.db_path,
                )
            )
            clock.return_value = now + 0.04
            self.assertEqual(
                len(get_sessions_for_ip(self.client_ip, **self._kwargs())),
                1,
            )
            clock.return_value = now + 0.10
            self.assertEqual(
                get_sessions_for_ip(self.client_ip, **self._kwargs()),
                [],
            )

    def test_unexpired_session_uins_excludes_ticket_only_and_expired_rows(self) -> None:
        self.assertEqual(
            get_unexpired_session_uins(db_path=self.db_path),
            set(),
        )
        now = time.time()
        with patch("server.tgame_ticket_state.time.time", return_value=now) as clock:
            self.assertTrue(
                save_transport_key(
                    self.ticket,
                    self.uin,
                    self.client_ip,
                    self.transport_key,
                    ttl_seconds=0.03,
                    **self._kwargs(),
                )
            )
            self.assertEqual(
                get_unexpired_session_uins(db_path=self.db_path),
                {self.uin},
            )
            clock.return_value = now + 0.05
            self.assertEqual(
                get_unexpired_session_uins(db_path=self.db_path),
                set(),
            )

    def test_expired_ticket_row_is_removed_and_revocation_is_immediate(self) -> None:
        self.assertTrue(
            save_transport_key(
                self.ticket,
                self.uin,
                self.client_ip,
                self.transport_key,
                **self._kwargs(),
            )
        )
        self.assertTrue(delete_session(self.ticket, db_path=self.db_path))
        self.assertEqual(get_sessions_for_ip(self.client_ip, **self._kwargs()), [])

    def test_issue_rejects_bad_key_or_mode(self) -> None:
        with self.assertRaises(ValueError):
            issue_ticket(
                self.uin,
                self.client_ip,
                b"short",
                db_path=self.db_path,
                private_key_path=self.private_key_path,
            )
        with self.assertRaises(ValueError):
            issue_ticket(
                self.uin,
                self.client_ip,
                self.auth_key,
                mode=2,
                db_path=self.db_path,
                private_key_path=self.private_key_path,
            )


if __name__ == "__main__":
    unittest.main()
