import tempfile
import unittest
from pathlib import Path

from server.account_db import (
    DuplicateUsername,
    account_count,
    create_account,
    get_account_by_username,
    init_db,
    verify_account,
)


class AccountDbTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "accounts.sqlite3"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_first_account_gets_legacy_local_uin(self):
        account = create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        self.assertEqual(account["uin"], 10001)
        self.assertEqual(account_count(db_path=self.db), 1)

    def test_usernames_are_case_insensitive(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        with self.assertRaises(DuplicateUsername):
            create_account("playerone", "another-password", db_path=self.db)

    def test_password_is_verified(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        self.assertIsNotNone(
            verify_account("playerone", "correct-horse-1", db_path=self.db)
        )
        self.assertIsNone(
            verify_account("playerone", "wrong-password", db_path=self.db)
        )

    def test_profile_lookup_returns_public_fields_only(self):
        create_account("PlayerOne", "correct-horse-1", db_path=self.db)
        account = get_account_by_username("PLAYERONE", db_path=self.db)
        self.assertEqual(account["uin"], 10001)
        self.assertNotIn("password_hash", account)
        self.assertNotIn("password_salt", account)


if __name__ == "__main__":
    unittest.main()
