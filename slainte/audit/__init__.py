"""
Integrity and audit (Andrew).

Two features that protect integrity and non-repudiation:
  - a tamper evident audit log (log.py): an HMAC-SHA256 hash chain
  - Ed25519 digital signatures on records, signed by their author

other parts of the app record events by calling log_event().
"""

from flask import Blueprint

bp = Blueprint("audit", __name__, url_prefix="/audit")


from . import demo, routes  # noqa: E402,F401