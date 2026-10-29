"""
Accounts and access: registration, login, roles and sessions.

All the auth pages live in a Flask "blueprint", a self-contained group of
routes that create_app() plugs into the main app. The other parts of the
project (records, audit) get their own blueprints the same way.

FOR THE REST OF THE GROUP: to find out who is logged in, use

    from slainte.auth import current_user

    user = current_user()      # None if nobody is logged in
    user["id"], user["username"], user["full_name"], user["role"]

`role` is one of "patient", "doctor" or "admin".
"""

from flask import Blueprint

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Imported at the bottom so they can attach themselves to bp.
from . import routes  # noqa: E402,F401
from .session import current_user  # noqa: E402,F401
