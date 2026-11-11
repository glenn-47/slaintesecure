"""
Accounts and access: registration, login, two-factor authentication,
roles and sessions.

All the auth pages live in a Flask "blueprint", a self-contained group of
routes that create_app() plugs into the main app. The other parts of the
project (records, audit) get their own blueprints the same way.

FOR THE REST OF THE GROUP:

    from slainte.auth import current_user, login_required, role_required

    user = current_user()      # None if nobody is logged in
    user["id"], user["username"], user["full_name"], user["role"]

    @login_required                    # page needs any logged-in user
    @role_required("doctor")           # page needs a particular role

`role` is one of "patient", "doctor" or "admin".
"""

from flask import Blueprint

# cli_group=None makes our terminal commands top-level, e.g.
# "flask --app run create-user" instead of "flask --app run auth create-user".
bp = Blueprint("auth", __name__, url_prefix="/auth", cli_group=None)

# Imported after bp exists, because these files attach themselves to it.
#
# The order of the two groups matters. The helpers come first, so that
# `from slainte.auth import current_user` already works by the time the
# pages load. The pages import the audit log, which loads records, which
# imports those helpers from here: a circle that only closes if the
# helpers are defined before the pages start loading.
from .decorators import login_required, role_required  # noqa: E402,F401
from .session import current_user  # noqa: E402,F401

from . import cli, routes, two_factor  # noqa: E402,F401
