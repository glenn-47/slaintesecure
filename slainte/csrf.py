"""
CSRF protection for every form in the app.

THE ATTACK: Cross-Site Request Forgery. A malicious website makes a
logged-in user's browser secretly submit one of our forms (e.g. "share my
records with this doctor"). The browser sends our session cookie along,
so without protection the request would look genuine.

THE DEFENCE: each session gets a secret random token. Every form we serve
includes it in a hidden field, and every POST must send it back. Another
website can't read our pages, so it can't know the token.

Usage in any form template:
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
"""

import hmac
import secrets

from flask import abort, request, session


def generate_csrf_token():
    """Return this session's CSRF token, creating one if needed."""
    if "csrf_token" not in session:
        # 32 random bytes from a cryptographically secure generator.
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf_token():
    """Reject any POST request whose token doesn't match the session's."""
    if request.method != "POST":
        return

    expected = session.get("csrf_token")
    sent = request.form.get("csrf_token", "")

    # compare_digest takes the same time whether the first character or
    # the last one differs, so attackers can't guess the token bit by bit
    # by timing the response.
    if not expected or not hmac.compare_digest(expected, sent):
        abort(400, description="Invalid or missing CSRF token.")


def init_app(app):
    """Check every request, and make csrf_token() usable in templates."""
    app.before_request(check_csrf_token)
    app.jinja_env.globals["csrf_token"] = generate_csrf_token
