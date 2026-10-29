"""Web pages for accounts: registration (login comes next)."""

import re
import sqlite3

from flask import flash, redirect, render_template, request, url_for

from ..db import get_db
from . import bp
from .passwords import hash_password, password_problems

# 3-30 characters: letters, numbers, dots, underscores and hyphens only.
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,30}$")


@bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Show the registration form, and create the account when it's submitted.

    Anyone can register, but only as a PATIENT. Letting people pick
    "doctor" here would let anyone give themselves access to other
    patients' records. Doctor accounts will be created by an admin.
    """
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

    flash("Account created. You can log in once login is added.", "success")
    return redirect(url_for("home"))
