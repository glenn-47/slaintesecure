"""
Access control: decorators that protect pages.

Put one of these above a route to control who can open it:

    from slainte.auth import login_required, role_required

    @bp.route("/my-records")
    @login_required                      # any logged-in user
    def my_records(): ...

    @bp.route("/patients")
    @role_required("doctor", "admin")    # only these roles
    def patients(): ...

The check runs on the server for every request, so hiding a link or
button in the page is never the only protection. Typing the URL directly
still gets blocked.
"""

from functools import wraps

from flask import abort, flash, g, redirect, request, url_for

from .session import current_user


def login_required(view):
    """Only allow logged-in users. Others are sent to the login page."""

    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if current_user() is None:
            # If their session just timed out, they've already been told.
            if not g.get("session_expired"):
                flash("Please log in to see that page.", "error")
            # Remember where they were going, so login can send them back.
            next_page = request.full_path if request.query_string else request.path
            return redirect(url_for("auth.login", next=next_page))
        return view(*args, **kwargs)

    return wrapped_view


def role_required(*allowed_roles):
    """
    Only allow logged-in users whose role is in allowed_roles.

    Logged-in users with the wrong role get a 403 Forbidden page. This is
    the principle of least privilege: each role can only reach what it
    needs, e.g. a patient can never open the doctors' patient list.
    """

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped_view(*args, **kwargs):
            if current_user()["role"] not in allowed_roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped_view

    return decorator
