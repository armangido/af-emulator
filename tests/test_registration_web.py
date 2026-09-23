import tempfile
import unittest
from pathlib import Path
from unittest import mock

import server.account_db as account_db
import web.app as web_app
from server.account_db import account_count, get_account_by_username, init_db


class RegistrationWebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "web-test.sqlite3"
        init_db(self.db)

        self.original_db_path = web_app.DB_PATH
        web_app.DB_PATH = self.db
        web_app.app.config.update(
            TESTING=True,
            SECRET_KEY="test-secret",
        )
        self.client = web_app.app.test_client()

        original = account_db._hash_password

        def _fast(password, *, salt=None, iterations=None):
            return original(password, salt=salt, iterations=2)

        self.hash_patch = mock.patch.object(account_db, "_hash_password", side_effect=_fast)
        self.hash_patch.start()

    def tearDown(self):
        self.hash_patch.stop()
        web_app.DB_PATH = self.original_db_path
        self.tmp.cleanup()

    def _csrf(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess:
            return sess["_csrf"]

    def _register(self, username="PlayerOne", password="correct-horse-1"):
        return self.client.post(
            "/register",
            data={
                "csrf_token": self._csrf(),
                "username": username,
                "password": password,
                "confirm_password": password,
            },
        )

    def test_register_page_loads(self):
        response = self.client.get("/register")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create your account", response.data)
        self.assertIn(b'name="csrf_token"', response.data)

    def test_root_route_shows_registration_page(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Create your account", response.data)

    def test_successful_registration_creates_account(self):
        response = self._register()

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration complete", response.data)
        self.assertIn(b"10001", response.data)
        self.assertEqual(account_count(db_path=self.db), 1)
        self.assertEqual(
            get_account_by_username("playerone", db_path=self.db)["uin"],
            10001,
        )

    def test_second_registration_gets_next_uin(self):
        first = self._register("PlayerOne", "correct-horse-1")
        second = self._register("PlayerTwo", "correct-horse-2")

        self.assertIn(b"10001", first.data)
        self.assertIn(b"10002", second.data)
        self.assertEqual(account_count(db_path=self.db), 2)

    def test_missing_csrf_is_rejected_without_creating_account(self):
        response = self.client.post(
            "/register",
            data={
                "username": "PlayerOne",
                "password": "correct-horse-1",
                "confirm_password": "correct-horse-1",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Registration form expired", response.data)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_bad_csrf_is_rejected(self):
        self._csrf()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": "not-the-session-token",
                "username": "PlayerOne",
                "password": "correct-horse-1",
                "confirm_password": "correct-horse-1",
            },
        )

        self.assertIn(b"Registration form expired", response.data)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_password_mismatch_is_rejected(self):
        response = self.client.post(
            "/register",
            data={
                "csrf_token": self._csrf(),
                "username": "PlayerOne",
                "password": "correct-horse-1",
                "confirm_password": "different-password",
            },
        )

        self.assertIn(b"Passwords do not match", response.data)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_duplicate_username_is_rejected_case_insensitively(self):
        self._register("PlayerOne", "correct-horse-1")
        response = self._register("playerone", "correct-horse-2")

        self.assertIn(b"already registered", response.data)
        self.assertEqual(account_count(db_path=self.db), 1)

    def test_invalid_username_error_is_rendered(self):
        response = self._register("bad user", "correct-horse-1")

        self.assertIn(b"Username must be 3-24 characters", response.data)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_short_password_error_is_rendered(self):
        response = self._register("PlayerOne", "short")

        self.assertIn(b"Password must be at least 8 characters", response.data)
        self.assertEqual(account_count(db_path=self.db), 0)

    def test_healthz_reports_account_count(self):
        self._register("PlayerOne", "correct-horse-1")

        response = self.client.get("/healthz")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["ok"], True)
        self.assertEqual(payload["accounts"], 1)
        self.assertEqual(payload["database"], self.db.name)

    def test_security_headers_are_present(self):
        response = self.client.get("/register")

        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "same-origin")
        self.assertIn(
            "frame-ancestors 'none'",
            response.headers["Content-Security-Policy"],
        )

    def test_oversized_request_is_rejected(self):
        token = self._csrf()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "username": "PlayerOne",
                "password": "x" * (17 * 1024),
                "confirm_password": "x" * (17 * 1024),
            },
        )
        self.assertEqual(response.status_code, 413)
        self.assertEqual(account_count(db_path=self.db), 0)


if __name__ == "__main__":
    unittest.main()
