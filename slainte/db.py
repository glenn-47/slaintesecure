"""
Database helpers for Sláinte Secure.

We use SQLite, which is built into Python and keeps the whole database in
one file (instance/slainte.sqlite3). Everyone in the group uses these
helpers instead of opening their own connections.

Usage inside a route:
    from slainte.db import get_db
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

Always use "?" placeholders like above and never build SQL by gluing
strings together. The placeholders stop SQL injection, because the
values are sent separately from the SQL and can't change its meaning.
"""

import sqlite3

import click
from flask import current_app, g


def get_db():
    """
    Return the database connection for the current request.

    Flask's `g` object lives for one request, so the connection is opened
    the first time it's needed and reused for the rest of that request.
    """
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        # Rows behave like dictionaries: row["username"] instead of row[1].
        g.db.row_factory = sqlite3.Row
        # SQLite doesn't enforce foreign keys unless you switch it on.
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    """Close the connection at the end of each request, if one was opened."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create any missing tables by running schema.sql."""
    db = get_db()
    with current_app.open_resource("schema.sql") as f:
        db.executescript(f.read().decode("utf-8"))
    db.commit()


@click.command("reset-db")
def reset_db_command():
    """
    Delete ALL data and rebuild the database from schema.sql.

    Useful while developing, e.g. after someone changes a table in
    schema.sql. Run with:  flask --app run reset-db
    """
    db = get_db()
    tables = db.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    db.execute("PRAGMA foreign_keys = OFF")
    for table in tables:
        db.execute(f'DROP TABLE IF EXISTS "{table["name"]}"')
    db.commit()
    init_db()
    click.echo("Database reset.")


def init_app(app):
    """Hook the database into the Flask app (called from create_app)."""
    app.teardown_appcontext(close_db)
    app.cli.add_command(reset_db_command)

    # Make sure all tables exist when the app starts.
    with app.app_context():
        init_db()
