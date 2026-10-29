"""
Accounts and access: registration, login, roles and sessions.

All the auth pages live in a Flask "blueprint", a self-contained group of
routes that create_app() plugs into the main app. The other parts of the
project (records, audit) get their own blueprints the same way.
"""

from flask import Blueprint

bp = Blueprint("auth", __name__, url_prefix="/auth")

# Imported at the bottom so the routes can attach themselves to bp.
from . import routes  # noqa: E402,F401
