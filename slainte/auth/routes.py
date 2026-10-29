"""Web pages for accounts: registration, login and logout."""

import re
import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, flash, redirect, render_template, request, session, url_for

from ..db import get_db
from . import bp
from .passwords import hash_password, needs_rehash, password_problems, verify_password
from .session import current_user

# 3-30 characters: letters, numbers, dots, underscores and hyphens only.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,30}$")

# A real Argon2 hash of a throwaway password, made once when the app starts.
# When someone tries to log in with a username that doesn't exist, we still
# check their password against this, so the response takes just as long as
# for a real account. Otherwise an attacker could tell which usernames exist
# by timing the replies ("timing attack" / username enumeration).
_DUMMY_HASH = hash_password("not-a-real-password-just-for-timing")


# ============================== Registration ==============================

@bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Show the registration form, and create the account when it's submitted.

    Anyone can register, but only as a PATIENT. Letting people pick
    "doctor" here would let anyone give themselves access to other
    patients' records. Doctor accounts will be created by an admin.
    """
    if current_user():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("auth/register.html", form={})

    form = request.form
    username = form.get("username", "").strip()
    full_name = form.get("full_name", "").strip()
    password = form.get("password", "")
    confirm = form.get("confirm_password", "")

    # Validate everything first and collect all the errors at once.
    errors = []
    if not USERNAME_PATTERN.match(username):
        errors.append("Username must be 3-30 characters: letters, numbers, . _ or -")
    if not 1 <= len(full_name) <= 100:
        errors.append("Please enter your full name (up to 100 characters).")
    if password != confirm:
        errors.append("The passwords don't match.")
    errors.extend(password_problems(password, username))

    if errors:
        for error in errors:
            flash(error, "error")
        # Send back what they typed (except passwords) so they don't
        # have to fill in the whole form again.
        return render_template("auth/register.html", form=form), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, full_name, password_hash, role) "
            "VALUES (?, ?, ?, 'patient')",
            (username, full_name, hash_password(password)),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # The UNIQUE rule on username caught a duplicate.
        flash("That username is already taken.", "error")
        return render_template("auth/register.html", form=form), 400

    flash("Account created. You can now log in.", "success")
    return redirect(url_for("auth.login"))


# ================================= Login =================================

@bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Log a user in, locking the account after too many wrong passwords.

    Security measures here:
      - Same error for "no such user" and "wrong password", so attackers
        can't use the form to discover which usernames exist.
      - Account lockout after LOGIN_MAX_ATTEMPTS failures in a row, to stop
        brute-force password guessing.
      - The session is cleared and rebuilt on login (prevents session
        fixation: an attacker planting a session before you log in).
    """
    if current_user():
        return redirect(url_for("home"))

    if request.method == "GET":
        return render_template("auth/login.html", username="")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    db = get_db()
    user = db.execute(
        "SELECT id, username, password_hash, failed_logins, locked_until "
        "FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    generic_error = "Incorrect username or password."

    # --- Unknown username: do the same work as a real check, then fail. ---
    if user is None:
        verify_password(_DUMMY_HASH, password)
        flash(generic_error, "error")
        return render_template("auth/login.html", username=username), 401

    now = datetime.now(timezone.utc)

    # --- Locked account: refuse without even checking the password, ---
    # --- so an attacker can't keep guessing during the lockout.      ---
    if user["locked_until"]:
        locked_until = datetime.fromisoformat(user["locked_until"])
        if now < locked_until:
            minutes_left = int((locked_until - now).total_seconds() // 60) + 1
            # This does reveal the account exists, a deliberate trade-off:
            # a genuine user needs to know why they can't log in.
            flash(
                f"Too many failed attempts. This account is locked for "
                f"{minutes_left} more minute(s).",
                "error",
            )
            return render_template("auth/login.html", username=username), 403

    # --- Wrong password: count it, and lock the account if needed. ---
    if not verify_password(user["password_hash"], password):
        failures = user["failed_logins"] + 1
        max_attempts = current_app.config["LOGIN_MAX_ATTEMPTS"]

        if failures >= max_attempts:
            lock_minutes = current_app.config["LOGIN_LOCKOUT_MINUTES"]
            locked_until = now + timedelta(minutes=lock_minutes)
            db.execute(
                "UPDATE users SET failed_logins = 0, locked_until = ? WHERE id = ?",
                (locked_until.isoformat(), user["id"]),
            )
            flash(
                f"Too many failed attempts. This account is locked for "
                f"{lock_minutes} minutes.",
                "error",
            )
        else:
            db.execute(
                "UPDATE users SET failed_logins = ? WHERE id = ?",
                (failures, user["id"]),
            )
            flash(generic_error, "error")

        db.commit()
        return render_template("auth/login.html", username=username), 401

    # --- Correct password: reset the counters and start the session. ---
    db.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?",
        (user["id"],),
    )

    # If the hash was made with weaker Argon2 settings than we use now,
    # upgrade it while we have the plain password (only possible at login).
    if needs_rehash(user["password_hash"]):
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (hash_password(password), user["id"]),
        )
    db.commit()

    session.clear()
    session["user_id"] = user["id"]

    flash(f"Welcome back, {user['username']}.", "success")
    return redirect(url_for("home"))


# ================================= Logout =================================

@bp.route("/logout", methods=["POST"])
def logout():
    """
    Log the user out by wiping the session.

    POST only (from a form with a CSRF token), never a plain link: if
    logout were a GET link, any other website could log our users out just
    by embedding that link in an image tag.
    """
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))
