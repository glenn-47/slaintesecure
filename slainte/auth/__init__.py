"""
Accounts and access: registration, login, two-factor authentication,
roles and sessions.
"""

from flask import Blueprint

bp = Blueprint("auth", __name__, url_prefix="/auth", cli_group=None)

from .decorators import login_required, role_required  # noqa: E402,F401
from .session import current_user  # noqa: E402,F401

from . import cli, routes, two_factor  # noqa: E402,F401
