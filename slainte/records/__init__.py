"""
Encrypted records: creating, viewing and sharing health records.

Sets up the blueprint for records and sends them to the routes.py file
"""

from flask import Blueprint

bp = Blueprint("records", __name__, url_prefix="/records")

# Imported at the bottom so they can attach themselves to bp.
from . import routes  # noqa: E402,F401
from .access import can_view  # noqa: E402,F401
