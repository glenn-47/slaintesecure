"""
Terminal commands for managing accounts.

Doctors and admins can't sign up through the website (otherwise anyone
could make themselves a doctor), so they're created from the terminal by
whoever runs the server:

    flask --app run create-user --role doctor
    flask --app run create-user --role admin

It asks for the username, full name and password. The password is hidden
as you type and goes through the same rules and Argon2 hashing as the
sign-up page.

If someone loses the phone with their authenticator app, they can't log
in to turn two-factor authentication off themselves, so it's reset from
the terminal:

    flask --app run reset-2fa USERNAME
"""

import sqlite3

import click

from ..audit.log import log_event
from ..db import get_db
from . import bp, totp
from .passwords import hash_password, password_problems
from .routes import USERNAME_PATTERN


@bp.cli.command("create-user")
@click.option(
    "--role",
    type=click.Choice(["patient", "doctor", "admin"]),
    default="doctor",
    show_default=True,
    help="What kind of account to create.",
)
def create_user_command(role):
    """Create a user account from the terminal."""
    username = click.prompt("Username").strip()
    if not USERNAME_PATTERN.match(username):
        raise click.ClickException(
            "Username must be 3-30 characters: letters, numbers, . _ or -"
        )

    full_name = click.prompt("Full name").strip()
    if not 1 <= len(full_name) <= 100:
        raise click.ClickException("Full name must be 1-100 characters.")

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
    problems = password_problems(password, username)
    if problems:
        raise click.ClickException(" ".join(problems))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, full_name, password_hash, role) "
            "VALUES (?, ?, ?, ?)",
            (username, full_name, hash_password(password), role),
        )
        db.commit()
    except sqlite3.IntegrityError:
        raise click.ClickException("That username is already taken.")

    click.echo(f"Created {role} account '{username}'.")


@bp.cli.command("reset-2fa")
@click.argument("username")
def reset_two_factor_command(username):
    """Turn off two-factor authentication for USERNAME."""
    user = get_db().execute(
        "SELECT id FROM users WHERE username = ?", (username,)
    ).fetchone()
    if user is None:
        raise click.ClickException(f"No user called '{username}'.")

    if not totp.is_enabled(user["id"]):
        click.echo(f"'{username}' doesn't have two-factor authentication on.")
        return

    totp.disable(user["id"])
    log_event("two_factor_disabled", user["id"], "reset from the terminal")
    click.echo(f"Two-factor authentication turned off for '{username}'.")
