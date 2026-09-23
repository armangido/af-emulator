"""Local registration website for the Assault Fire emulator."""

from __future__ import annotations

import hmac
import os
import secrets
import sys
from pathlib import Path

from flask import Flask, jsonify, render_template, request, session

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.account_db import (  # noqa: E402
    AccountError,
    DuplicateUsername,
    account_count,
    create_account,
    init_db,
)

app = Flask(__name__, template_folder="templates", static_folder="static")

secret = os.environ.get("AF_WEB_SECRET")
if not secret:
    secret = secrets.token_hex(32)
    print(
        "[WEB] AF_WEB_SECRET is not set; using a temporary secret for this process.",
        flush=True,
    )

app.config.update(
    SECRET_KEY=secret,
    MAX_CONTENT_LENGTH=16 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

DB_PATH = init_db()


def csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token


app.jinja_env.globals["csrf_token"] = csrf_token


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )
    return response


@app.route("/", methods=["GET"])
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    registered = None
    entered_username = ""

    if request.method == "POST":
        submitted_csrf = request.form.get("csrf_token", "")
        expected_csrf = session.get("_csrf", "")
        if (
            not submitted_csrf
            or not expected_csrf
            or not hmac.compare_digest(submitted_csrf, expected_csrf)
        ):
            error = "Registration form expired. Refresh the page and try again."
        else:
            entered_username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if password != confirm_password:
                error = "Passwords do not match."
            else:
                try:
                    registered = create_account(
                        entered_username,
                        password,
                        db_path=DB_PATH,
                    )
                    session["_csrf"] = secrets.token_urlsafe(32)
                except DuplicateUsername as exc:
                    error = str(exc)
                except AccountError as exc:
                    error = str(exc)

    return render_template(
        "register.html",
        error=error,
        registered=registered,
        entered_username=entered_username,
    )


@app.get("/healthz")
def healthz():
    return jsonify(
        {
            "ok": True,
            "database": DB_PATH.name,
            "accounts": account_count(db_path=DB_PATH),
        }
    )


if __name__ == "__main__":
    host = os.environ.get("AF_WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("AF_WEB_PORT", "8080"))
    print(f"[WEB] Registration: http://{host}:{port}/register", flush=True)
    print(f"[WEB] Account DB: {DB_PATH}", flush=True)
    app.run(host=host, port=port, debug=False)
