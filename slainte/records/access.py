"""
Who is allowed to read a record?

This is the one place that answers that question, and every records page
calls it. Keeping the rule in a single function means a page can't
accidentally use a weaker check than the others.

WHY NOT JUST CHECK THE ROLE?
@role_required("doctor") only proves someone IS a doctor, not that they're
THIS patient's doctor. Without a per-record check, any doctor could change
the number in /records/5 to /records/6 and read a stranger's record. That
attack is called IDOR (Insecure Direct Object Reference), and it's one of
the most common access-control bugs on the web (OWASP A01: Broken Access
Control). So as well as the role, we check how the user is connected to
this particular record.

The rule (least privilege):
  - the patient the record is about can read it,
  - the doctor who wrote it can read it,
  - a doctor the patient has shared it with can read it,
  - nobody else, including admins. Admins manage accounts; they have no
    medical reason to read records, so they aren't given access.
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
