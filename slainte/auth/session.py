"""
Who is logged in?

When someone logs in, we store only their user ID in the session cookie.
Flask signs that cookie with the app's secret key (HMAC-SHA1 via the
itsdangerous library), so a user can't edit it to become someone else:
any change breaks the signature and Flask throws the cookie away.

On every request we look the user up in the database again, rather than
trusting details stored in the cookie. That way, if an account is changed
(e.g. a role is removed or the account is locked), it takes effect on the
very next page they load.
"""

from flask import g, session

from ..db import get_db
from . import bp


@bp.before_app_request
def load_logged_in_user():
    """Runs before every request in the app and sets g.user."""
    user_id = session.get("user_id")

    if user_id is None:
        g.user = None
        return

    g.user = get_db().execute(
        "SELECT id, username, full_name, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    # The account no longer exists (e.g. the database was reset):
    # throw away the stale session.
    if g.user is None:
        session.clear()


def current_user():
    """
    Return the logged-in user, or None if nobody is logged in.

    The result works like a dictionary:
        user["id"], user["username"], user["full_name"], user["role"]
    """
    return g.get("user")


@bp.app_context_processor
def inject_current_user():
    """Make `current_user` available in every HTML template."""
    return {"current_user": current_user()}
