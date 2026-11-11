"""
This file allows the users to access certain records based off of their roles

E.G.
Patient receives a record from a doctor, and then patient is able to 
view and share the record with other doctors only.
Doctors have access to their records that they have created, and records that
the patients have sent them.
"""

from ..db import get_db


def can_view(user, record):
    """True if `user` may read `record` (both are database rows)."""
    if user is None or record is None:
        return False

    if user["role"] == "patient":
        return record["patient_id"] == user["id"]

    if user["role"] == "doctor":
        if record["author_id"] == user["id"]:
            return True
        shared = get_db().execute(
            "SELECT 1 FROM record_shares WHERE record_id = ? AND doctor_id = ?",
            (record["id"], user["id"]),
        ).fetchone()
        return shared is not None

    return False
