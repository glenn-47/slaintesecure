"""
Encrypted records: creating, viewing and (next) sharing health records.

Like auth/, this is a Flask blueprint that create_app() plugs into the
main app. All pages live under /records.

Every record is encrypted with slainte/crypto.py before it is saved, so
the database only ever holds ciphertext. See crypto.py for the details.

FOR THE REST OF THE GROUP:

    from slainte.records import can_view

    can_view(user, record_row)   # True if this user may read the record
"""

from flask import Blueprint

bp = Blueprint("records", __name__, url_prefix="/records")

# Imported at the bottom so they can attach themselves to bp.
from . import routes  # noqa: E402,F401
from .access import can_view  # noqa: E402,F401
