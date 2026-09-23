import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server.account_db as account_db
from server.account_db import (
    DuplicateUsername,
    InvalidPassword,
    InvalidUsername,
    account_count,
    create_account,
    get_account_by_username,
    init_db,
    normalize_username,
    validate_password,
    verify_account,
)


def fast_hash_password(password, *, salt=None, iterations=2):
    return account_db._hash_password.__wrapped__(password, salt=salt, iterations=2)


class AccountDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "accounts.sqlite3"
        init_db(self.db)

        # Keep tests fast without weakening production settings.
        original = account_db._hash_password

        def _fast(password, *, salt=None, iterations=None):
            return original(password, salt=salt, iterations=2)

        self.hash_patch = mock.patch.object(account_db, "_hash_password", side_effect=_fast)
        self.hash_patch.start()

    def tearDown(self):
        self.hash_patch.stop()
        self.tmp.cleanup()

    def test_first_account_gets_legacy_local_uin(self):
        account = create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        self.assertEqual(account["uin"], 10001)
        self.assertEqual(account_count(db_path=self.db), 1)

    def test_uins_increment_for_additional_accounts(self):
        first = create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        second = create_account("PlayerTwo", "correct-horse-2", db_path=self.db)
        third = create_account("PlayerThree", "correct-horse-3", db_path=self.db)

        self.assertEqual(first["uin"], 10001)
        self.assertEqual(second["uin"], 10002)
        self.assertEqual(third["uin"], 10003)

    def test_usernames_are_case_insensitive(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        with self.assertRaises(DuplicateUsername):
            create_account("playerone", "another-password", db_path=self.db)

    def test_username_is_trimmed_and_normalized(self):
        account = create_account("  Player.One  ", "correct-horse-1", db_path=self.db)
        self.assertEqual(account["username"], "Player.One")
        self.assertEqual(normalize_username(" PLAYER.ONE "), "player.one")
        self.assertEqual(
            get_account_by_username("player.one", db_path=self.db)["uin"],
            10001,
        )

    def test_invalid_usernames_are_rejected(self):
        for username in ("ab", "bad space", "bad@email", "x" * 25):
            with self.subTest(username=username):
                with self.assertRaises(InvalidUsername):
                    create_account(username, "correct-horse-1", db_path=self.db)

        self.assertEqual(account_count(db_path=self.db), 0)

    def test_invalid_password_lengths_are_rejected(self):
        with self.assertRaises(InvalidPassword):
            validate_password("short")
        with self.assertRaises(InvalidPassword):
            validate_password("x" * 73)

    def test_password_is_verified(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)

        self.assertIsNotNone(
            verify_account("playerone", "correct-horse-1", db_path=self.db)
        )
        self.assertIsNone(
            verify_account("playerone", "wrong-password", db_path=self.db)
        )

    def test_password_is_not_stored_as_plaintext(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)

        conn = sqlite3.connect(self.db)
        try:
            row = conn.execute(
                "SELECT password_hash, password_salt, password_iterations "
                "FROM accounts WHERE uin = 10001"
            ).fetchone()
        finally:
            conn.close()

        self.assertIsNotNone(row)
        password_hash, salt, iterations = row
        self.assertNotEqual(password_hash, b"correct-horse-1")
        self.assertGreaterEqual(len(password_hash), 32)
        self.assertEqual(len(salt), 16)
        self.assertEqual(iterations, 2)

    def test_profile_row_is_created_with_no_nickname(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)

        conn = sqlite3.connect(self.db)
        try:
            row = conn.execute(
                "SELECT uin, nickname FROM profiles WHERE uin = 10001"
            ).fetchone()
        finally:
            conn.close()

        self.assertEqual(row, (10001, None))

    def test_profile_lookup_returns_public_fields_only(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        account = get_account_by_username("PLAYERONE", db_path=self.db)

        self.assertEqual(account["uin"], 10001)
        self.assertNotIn("password_hash", account)
        self.assertNotIn("password_salt", account)
        self.assertNotIn("password_iterations", account)

    def test_disabled_account_cannot_authenticate(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)

        conn = sqlite3.connect(self.db)
        try:
            conn.execute(
                "UPDATE accounts SET status = 'disabled' WHERE uin = 10001"
            )
            conn.commit()
        finally:
            conn.close()

        self.assertIsNone(
            verify_account("PlayerOne", "correct-horse-1", db_path=self.db)
        )

    def test_verify_can_update_last_login_timestamp(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)

        before = get_account_by_username("PlayerOne", db_path=self.db)
        self.assertIsNone(before["last_login_at"])

        verified = verify_account(
            "PlayerOne",
            "correct-horse-1",
            db_path=self.db,
            update_last_login=True,
        )

        self.assertIsNotNone(verified["last_login_at"])
        after = get_account_by_username("PlayerOne", db_path=self.db)
        self.assertEqual(after["last_login_at"], verified["last_login_at"])

    def test_init_db_is_idempotent(self):
        init_db(self.db)
        init_db(self.db)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_unknown_account_returns_none(self):
        self.assertIsNone(get_account_by_username("MissingUser", db_path=self.db))
        self.assertIsNone(
            verify_account("MissingUser", "correct-horse-1", db_path=self.db)
        )


if __name__ == "__main__":
    unittest.main()
