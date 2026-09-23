"""SQLite account storage for the Assault Fire emulator.

This module is intentionally independent from the network protocol so the web
registration service and the emulator can share one authoritative account DB.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB_PATH = Path(
    os.environ.get(
        "AF_ACCOUNT_DB",
        str(Path(__file__).with_name("assaultfire_accounts.sqlite3")),
    )
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,24}$")
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 72
PBKDF2_ITERATIONS = int(os.environ.get("AF_PASSWORD_ITERATIONS", "600000"))
FIRST_UIN = 10001


class AccountError(ValueError):
    """Base class for account validation/storage errors."""


class InvalidUsername(AccountError):
    pass


class InvalidPassword(AccountError):
    pass


class DuplicateUsername(AccountError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_username(username: str) -> str:
    username = (username or "").strip()
    if not USERNAME_RE.fullmatch(username):
        raise InvalidUsername(
            "Username must be 3-24 characters and use only letters, numbers, '.', '_' or '-'."
        )
    return username.casefold()


def validate_password(password: str) -> None:
    if not isinstance(password, str):
        raise InvalidPassword("Password is required.")
    if len(password) < PASSWORD_MIN_LENGTH:
        raise InvalidPassword(
            f"Password must be at least {PASSWORD_MIN_LENGTH} characters."
        )
    if len(password) > PASSWORD_MAX_LENGTH:
        raise InvalidPassword(
            f"Password must be at most {PASSWORD_MAX_LENGTH} characters."
        )


def _hash_password(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = PBKDF2_ITERATIONS,
) -> tuple[bytes, bytes, int]:
    validate_password(password)
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return digest, salt, iterations


def connect(db_path: str | os.PathLike[str] | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db(db_path: str | os.PathLike[str] | None = None) -> Path:
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    conn = connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uin INTEGER NOT NULL UNIQUE CHECK (uin >= 10001),
                username TEXT NOT NULL,
                username_norm TEXT NOT NULL UNIQUE,
                password_hash BLOB NOT NULL,
                password_salt BLOB NOT NULL,
                password_iterations INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'disabled')),
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );

            CREATE TABLE IF NOT EXISTS profiles (
                uin INTEGER PRIMARY KEY,
                nickname TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (uin) REFERENCES accounts(uin) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_accounts_status
                ON accounts(status);
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')"
        )
        conn.commit()
    finally:
        conn.close()
    return path


def create_account(
    username: str,
    password: str,
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    username = (username or "").strip()
    username_norm = normalize_username(username)
    digest, salt, iterations = _hash_password(password)
    created_at = _utc_now()

    init_db(db_path)
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")

        existing = conn.execute(
            "SELECT 1 FROM accounts WHERE username_norm = ?",
            (username_norm,),
        ).fetchone()
        if existing:
            raise DuplicateUsername("That username is already registered.")

        row = conn.execute(
            "SELECT MAX(uin) AS max_uin FROM accounts"
        ).fetchone()
        max_uin = row["max_uin"] if row and row["max_uin"] is not None else FIRST_UIN - 1
        uin = max(FIRST_UIN, int(max_uin) + 1)

        conn.execute(
            """
            INSERT INTO accounts(
                uin, username, username_norm,
                password_hash, password_salt, password_iterations,
                status, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, 'active', ?)
            """,
            (
                uin,
                username,
                username_norm,
                digest,
                salt,
                iterations,
                created_at,
            ),
        )
        conn.execute(
            "INSERT INTO profiles(uin, nickname, created_at) VALUES(?, NULL, ?)",
            (uin, created_at),
        )
        conn.commit()
        return {
            "uin": uin,
            "username": username,
            "status": "active",
            "created_at": created_at,
        }
    except DuplicateUsername:
        conn.rollback()
        raise
    except sqlite3.IntegrityError as exc:
        conn.rollback()
        if "username_norm" in str(exc).lower():
            raise DuplicateUsername("That username is already registered.") from exc
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_account_by_username(
    username: str,
    *,
    db_path: str | os.PathLike[str] | None = None,
) -> dict[str, Any] | None:
    try:
        username_norm = normalize_username(username)
    except InvalidUsername:
        return None

    init_db(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT id, uin, username, username_norm, status,
                   created_at, last_login_at
            FROM accounts
            WHERE username_norm = ?
            """,
            (username_norm,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def verify_account(
    username: str,
    password: str,
    *,
    db_path: str | os.PathLike[str] | None = None,
    update_last_login: bool = False,
) -> dict[str, Any] | None:
    try:
        username_norm = normalize_username(username)
        validate_password(password)
    except AccountError:
        return None

    init_db(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT id, uin, username, username_norm, status, created_at,
                   last_login_at, password_hash, password_salt,
                   password_iterations
            FROM accounts
            WHERE username_norm = ?
            """,
            (username_norm,),
        ).fetchone()

        if not row or row["status"] != "active":
            return None

        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes(row["password_salt"]),
            int(row["password_iterations"]),
        )
        if not hmac.compare_digest(candidate, bytes(row["password_hash"])):
            return None

        if update_last_login:
            last_login_at = _utc_now()
            conn.execute(
                "UPDATE accounts SET last_login_at = ? WHERE id = ?",
                (last_login_at, row["id"]),
            )
            conn.commit()
        else:
            last_login_at = row["last_login_at"]

        return {
            "id": row["id"],
            "uin": row["uin"],
            "username": row["username"],
            "status": row["status"],
            "created_at": row["created_at"],
            "last_login_at": last_login_at,
        }
    finally:
        conn.close()


def account_count(
    *, db_path: str | os.PathLike[str] | None = None
) -> int:
    init_db(db_path)
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT COUNT(*) AS n FROM accounts").fetchone()
        return int(row["n"])
    finally:
        conn.close()
