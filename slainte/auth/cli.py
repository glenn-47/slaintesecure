"""
Terminal command for creating staff accounts.

Doctors and admins can't sign up through the website (otherwise anyone
could make themselves a doctor), so they're created from the terminal by
whoever runs the server:

    flask --app run create-user --role doctor
    flask --app run create-user --role admin

It asks for the username, full name and password. The password is hidden
as you type and goes through the same rules and Argon2 hashing as the
sign-up page.
"""

import sqlite3

import click

from ..db import get_db
from . import bp
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
