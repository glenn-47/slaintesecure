"""
Sláinte Secure: a secure healthcare records system.

This file builds the Flask application using the "application factory"
pattern: create_app() sets everything up and returns the app. Each part
of the project (accounts, records, audit) will plug in here as its own
module, so the three of us can work on separate files.
"""

import os
import secrets

from flask import Flask, render_template


def create_app():
    """Create and configure the Flask application."""
    # instance_relative_config=True means Flask keeps private, per-machine
    # files in an "instance" folder. That folder is in .gitignore, so the
    # database and the secret key never end up on GitHub.
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        SECRET_KEY=_load_or_create_secret_key(app.instance_path),
        DATABASE=os.path.join(app.instance_path, "slainte.sqlite3"),
        # Session cookie hardening:
        # HttpOnly stops JavaScript reading the cookie (limits XSS damage).
        SESSION_COOKIE_HTTPONLY=True,
        # SameSite=Lax stops the cookie being sent on most cross-site
        # requests, which helps protect against CSRF.
        SESSION_COOKIE_SAMESITE="Lax",
        # Account lockout: after this many wrong passwords in a row, the
        # account is locked for LOGIN_LOCKOUT_MINUTES. This stops attackers
        # guessing passwords over and over (brute force).
        LOGIN_MAX_ATTEMPTS=5,
        LOGIN_LOCKOUT_MINUTES=15,
    )

    # Set up the SQLite database and create any missing tables.
    from . import db
    db.init_app(app)

    # Reject any form submission that lacks a valid CSRF token.
    from . import csrf
    csrf.init_app(app)

    # Accounts and access: registration, login, logout, roles.
    from .auth import bp as auth_bp
    app.register_blueprint(auth_bp)

    @app.route("/")
    def home():
        return render_template("home.html")

    return app


def _load_or_create_secret_key(instance_path):
    """
    Return the secret key Flask uses to sign session cookies.

    Flask signs the session cookie with this key (HMAC), so a user can't
    edit their cookie to, say, change their role from patient to doctor.
    If the key leaked, anyone could forge a session, so:
      - it is generated randomly with the `secrets` module (a
        cryptographically secure random number generator), and
      - it is stored in the instance folder, which is never committed.
    """
    key_path = os.path.join(instance_path, "secret_key")

    if not os.path.exists(key_path):
        # 32 random bytes = 256 bits, written as 64 hex characters.
        with open(key_path, "w") as f:
            f.write(secrets.token_hex(32))

    with open(key_path) as f:
        return f.read().strip()
