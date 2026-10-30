"""
Who is logged in, and for how long?

When someone logs in, we store only their user ID (plus two timestamps)
in the session cookie. Flask signs that cookie with the app's secret key
(HMAC-SHA1 via the itsdangerous library), so a user can't edit it to
become someone else: any change breaks the signature and Flask throws the
cookie away.

On every request we look the user up in the database again, rather than
trusting details stored in the cookie. That way, if an account is changed
(e.g. a role is removed or the account is locked), it takes effect on the
very next page they load.

SESSION TIMEOUTS
A session ends automatically in two cases:
  - Idle timeout: no activity for SESSION_IDLE_MINUTES. Protects someone
    who walks away from a shared ward computer without logging out.
  - Absolute timeout: SESSION_MAX_HOURS after logging in, however active
    the user is. Limits how long a stolen session cookie stays useful.
"""

from datetime import datetime, timedelta, timezone

from flask import current_app, flash, g, session

from ..db import get_db
from . import bp


def start_session(user_id):
    """Log a user in: wipe any old session and record when it started."""
    # Clearing first prevents session fixation (an attacker planting a
    # session in your browser before you log in, then sharing it).
    session.clear()
    now = _now_iso()
    session["user_id"] = user_id
    session["login_at"] = now
    session["last_seen"] = now


@bp.before_app_request
def load_logged_in_user():
    """Runs before every request in the app: sets g.user and checks timeouts."""
    g.user = None
    user_id = session.get("user_id")

    if user_id is None:
        return

    if _session_expired():
        session.clear()
        g.session_expired = True
        flash("You were logged out because your session expired.", "error")
        return

    g.user = get_db().execute(
        "SELECT id, username, full_name, role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()

    if g.user is None:
        # The account no longer exists (e.g. the database was reset).
        session.clear()
        return

    session["last_seen"] = _now_iso()


def _session_expired():
    """True if the session hit the idle or the absolute timeout."""
    try:
        now = datetime.now(timezone.utc)
        last_seen = datetime.fromisoformat(session["last_seen"])
        login_at = datetime.fromisoformat(session["login_at"])
    except (KeyError, ValueError):
        # Missing or broken timestamps: treat the session as expired.
        return True

    idle_limit = timedelta(minutes=current_app.config["SESSION_IDLE_MINUTES"])
    max_age = timedelta(hours=current_app.config["SESSION_MAX_HOURS"])

    return now - last_seen > idle_limit or now - login_at > max_age


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


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
