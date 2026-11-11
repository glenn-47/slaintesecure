"""
Web pages for two-factor authentication (2FA).

  /auth/security      see whether 2FA is on, turn it on or off
  /auth/2fa/setup     scan the QR code and confirm a first code
  /auth/2fa/disable   turn 2FA off (needs the password)
  /auth/login/2fa     the second login step: enter the 6-digit code

The codes themselves are worked out in totp.py; this file is the pages.

2FA is opt-in per account. In a real hospital system it would be
mandatory for staff, since doctors and admins can reach the most data.
"""

from datetime import datetime, timedelta, timezone

from flask import (
    current_app, flash, make_response, redirect, render_template, request,
    session, url_for,
)
from markupsafe import Markup

from ..audit.log import log_event
from ..db import get_db
from . import bp, totp
from .decorators import login_required
from .passwords import verify_password
from .routes import _safe_next_page
from .session import current_user, start_session


# ============================ Second login step ============================

def _pending_login():
    """The half-finished login from the session, or None if missing or too old."""
    pending = session.get("pending_2fa")
    if not pending:
        return None

    try:
        started = datetime.fromisoformat(pending["at"])
    except (KeyError, TypeError, ValueError):
        return None

    limit = timedelta(minutes=current_app.config["TWO_FACTOR_PENDING_MINUTES"])
    if datetime.now(timezone.utc) - started > limit:
        return None
    return pending


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_two_factor():
    """
    Step two of logging in: the 6-digit code from the authenticator app.

    Wrong codes count towards the same lockout as wrong passwords. There
    are only a million possible codes, so without a limit an attacker who
    already has the password could simply try them all. And the failed
    counter is only reset once BOTH steps succeed, so getting the password
    right again doesn't hand out a fresh set of guesses.
    """
    pending = _pending_login()
    if pending is None:
        session.pop("pending_2fa", None)
        flash("Please log in again.", "error")
        return redirect(url_for("auth.login"))

    db = get_db()
    user = db.execute(
        "SELECT id, username, failed_logins, locked_until FROM users WHERE id = ?",
        (pending["user_id"],),
    ).fetchone()
    if user is None:
        session.pop("pending_2fa", None)
        return redirect(url_for("auth.login"))

    # If the account has been locked since the password step (e.g. by wrong
    # codes typed in another browser), stop here too. Otherwise an attacker
    # could keep several half-finished logins open and carry on guessing.
    now = datetime.now(timezone.utc)
    if user["locked_until"] and now < datetime.fromisoformat(user["locked_until"]):
        session.pop("pending_2fa", None)
        flash("This account is locked. Please try again later.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "GET":
        return render_template("auth/two_factor_login.html")

    code = request.form.get("code", "")

    # --- Wrong code: count it, and lock the account if needed. ---
    if not totp.verify_user_code(user["id"], code):
        failures = user["failed_logins"] + 1
        max_attempts = current_app.config["LOGIN_MAX_ATTEMPTS"]

        if failures >= max_attempts:
            lock_minutes = current_app.config["LOGIN_LOCKOUT_MINUTES"]
            locked_until = now + timedelta(minutes=lock_minutes)
            db.execute(
                "UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                (locked_until.isoformat(), user["id"]),
            )
            db.commit()
            session.pop("pending_2fa", None)
            log_event("account_locked", user["id"], f"after {failures} failed attempts")
            flash(
                f"Too many failed attempts. This account is locked for "
                f"{lock_minutes} minutes.",
                "error",
            )
            return redirect(url_for("auth.login"))

        db.execute(
            "UPDATE users SET failed_logins = ? WHERE id = ?", (failures, user["id"])
        )
        db.commit()
        log_event("login_failed", user["id"], "wrong 2FA code")
        flash("Incorrect code. Check your authenticator app and try again.", "error")
        return render_template("auth/two_factor_login.html"), 401

    # --- Correct code: both steps passed, so now the session starts. ---
    db.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
        (user["id"],),
    )
    db.commit()

    start_session(user["id"])
    log_event("login", user["id"], "with 2FA")

    flash(f"Welcome back, {user['username']}.", "success")
    return redirect(_safe_next_page(pending.get("next") or ""))


# ============================== Security page ==============================

@bp.route("/security")
@login_required
def security():
    """Shows whether 2FA is on for the logged-in user."""
    return render_template(
        "auth/security.html", two_factor_on=totp.is_enabled(current_user()["id"])
    )


# ================================ Turn 2FA on ==============================

@bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def two_factor_setup():
    """
    Show the QR code, then switch 2FA on once a first code is confirmed.

    Asking for a code before switching on proves the phone really has the
    secret. Without that check, a failed scan would lock the user out of
    their own account at the next login.
    """
    user = current_user()
    if totp.is_enabled(user["id"]):
        flash("Two-factor authentication is already on.", "success")
        return redirect(url_for("auth.security"))

    secret = totp.pending_secret(user["id"])
    status = 200

    if request.method == "POST":
        if totp.verify_user_code(user["id"], request.form.get("code", ""), activate=True):
            log_event("two_factor_enabled", user["id"])
            flash("Two-factor authentication is now on.", "success")
            return redirect(url_for("auth.security"))
        flash("That code wasn't right. Check the app and try the newest code.", "error")
        status = 400

    qr_svg = totp.qr_code_svg(totp.provisioning_uri(secret, user["username"]))
    key = totp.base32_secret(secret)

    response = make_response(render_template(
        "auth/two_factor_setup.html",
        # Markup() marks the SVG as safe to put in the page as-is. That's
        # fine here because our own code generated it; nothing in it comes
        # from user input.
        qr_svg=Markup(qr_svg) if qr_svg else None,
        # Shown in groups of four so it's easier to type by hand.
        setup_key=" ".join(key[i:i + 4] for i in range(0, len(key), 4)),
    ), status)
    # This page shows the secret, so tell the browser never to keep a copy
    # (otherwise it could be read back later from the cache or Back button).
    response.headers["Cache-Control"] = "no-store"
    return response


# =============================== Turn 2FA off ==============================

@bp.route("/2fa/disable", methods=["POST"])
@login_required
def two_factor_disable():
    """
    Turn 2FA off. Needs the account password again.

    Without that check, anyone who got hold of a logged-in session (e.g.
    an unlocked computer on a ward) could quietly remove the protection.
    """
    user = current_user()
    password_hash = get_db().execute(
        "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
    ).fetchone()["password_hash"]

    if not verify_password(password_hash, request.form.get("password", "")):
        flash("Incorrect password. Two-factor authentication is still on.", "error")
        return redirect(url_for("auth.security"))

    if totp.is_enabled(user["id"]):
        totp.disable(user["id"])
        log_event("two_factor_disabled", user["id"])
    flash("Two-factor authentication has been turned off.", "success")
    return redirect(url_for("auth.security"))
