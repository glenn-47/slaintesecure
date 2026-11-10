"""
Tamper-evident audit log.

Every entry stores an HMAC-SHA256 hash (entry_hash) computed over its own
fields AND the previous entry's hash (prev_hash). The entries therefore
form a chain:

    entry 1: hash(fields1 + GENESIS)
    entry 2: hash(fields2 + hash1)
    entry 3: hash(fields3 + hash2) ...

Editing an entry changes what its hash should be; deleting one leaves the
next entry pointing at a hash that no longer exists. Either way, verifying
the chain finds the first point where it breaks.

Why HMAC and not plain SHA-256: with plain SHA-256 anyone with database
access could edit an entry and recompute every hash after it. HMAC needs
the secret key in instance/ (see keys.py), so only the app can produce
valid hashes.

RULES FOR CALLERS:
  - Call log_event() AFTER your own db.commit(). It writes on its own
    connection, and SQLite allows only one writer at a time: if your
    connection still has uncommitted changes, log_event() waits for a
    lock that will never be released.
  - details holds IDs only (e.g. "record_id=12"). Never medical content,
    never passwords, never a typed-in username from a failed login
    (people sometimes type their password into the username box).
"""

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import current_app

from ..db import get_db

# prev_hash for the very first entry. Any fixed value works; 64 zeros is
# the same length as a real SHA-256 hex digest.
GENESIS_HASH = "0" * 64

# Every action the app is allowed to log. A typo like "login_fialed" raises
# an error instead of quietly writing an entry nobody will ever search for.
ACTIONS = {
    "login",
    "login_failed",
    "account_locked",
    "logout",
    "record_created",
    "record_viewed",
    "record_signed",
    "signature_failed",
    "integrity_check_failed",
}


def compute_hash(key, timestamp, user_id, action, details, prev_hash):
    """
    HMAC-SHA256 over one entry's fields plus the previous entry's hash.

    The fields are encoded as a JSON list rather than glued together as
    strings. Gluing is ambiguous: ("ab", "c") and ("a", "bc") would both
    become "abc" and get the same hash. A JSON list keeps the boundaries,
    so different entries always give different input bytes.

    verify_chain() uses this same function, so writing and checking can
    never disagree about the format.
    """
    message = json.dumps(
        [timestamp, user_id, action, details, prev_hash],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _connect():
    """
    A separate connection just for writing to the log (see RULES above).

    isolation_level=None turns off Python's automatic transactions, so
    log_event() controls exactly when its transaction starts and ends.
    """
    conn = sqlite3.connect(
        current_app.config["DATABASE"], isolation_level=None, timeout=10
    )
    conn.row_factory = sqlite3.Row
    return conn


def log_event(action, user_id=None, details=""):
    """Add one entry to the end of the audit log chain."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown audit action: {action!r}")

    # Normalise types BEFORE hashing. SQLite would store user_id "5" as the
    # integer 5, so the hash must be computed over 5 too, or verify_chain()
    # would later recompute a different hash and report false tampering.
    user_id = int(user_id) if user_id is not None else None
    details = str(details)

    key = current_app.config["AUDIT_HMAC_KEY"]
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    conn = _connect()
    try:
        # BEGIN IMMEDIATE takes the database's write lock BEFORE we read the
        # last hash. Without it, two requests logging at the same moment
        # could both read the same prev_hash and fork the chain into two
        # branches. With it, log writes happen strictly one at a time.
        conn.execute("BEGIN IMMEDIATE")

        last = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = last["entry_hash"] if last else GENESIS_HASH

        entry_hash = compute_hash(key, timestamp, user_id, action, details, prev_hash)

        cursor = conn.execute(
            "INSERT INTO audit_log "
            "(timestamp, user_id, action, details, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, user_id, action, details, prev_hash, entry_hash),
        )
        conn.execute("COMMIT")
        # Only after the entry is safely committed: if we saved the anchor
        # first and the commit failed, the anchor would point at an entry
        # that never existed and verification would cry wolf.
        _write_anchor(cursor.lastrowid, entry_hash)

    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()

    # ---------------------------------------------------------------------------
# Truncation anchor
#
# The hash chain catches edits, insertions and deletions in the MIDDLE of
# the log, because the entry after the change no longer links up. But if an
# attacker deletes the NEWEST entries, nothing comes after them, so the
# shorter chain still verifies. This is called truncation.
#
# Fix: after every entry, record its ID and hash in instance/audit_anchor.json,
# outside the database. verify_chain() checks that entry still exists with
# that hash. An attacker who can only edit the database can't update this
# file; one who can reach instance/ also has the HMAC key, so the anchor
# needs no extra protection beyond that. Real systems go further and send
# the latest hash to a separate server or a write-once log.
#
# NOTE: after `flask --app run reset-db`, also delete instance/audit_anchor.json,
# or verification will (correctly!) report that the log was wiped.
# ---------------------------------------------------------------------------

ANCHOR_FILENAME = "audit_anchor.json"


def _anchor_path():
    return os.path.join(current_app.instance_path, ANCHOR_FILENAME)


def _write_anchor(last_id, last_hash):
    """Record the newest entry. Written atomically, so it's never half-written."""
    path = _anchor_path()
    # Write to a uniquely named temp file, then swap it into place in one
    # step (os.replace). A crash mid-write leaves the old anchor intact
    # instead of a corrupted file.
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"last_id": last_id, "last_hash": last_hash}, f)
        os.replace(tmp, path)
    except OSError:
        # The entry itself is already committed and chained, so a failed
        # anchor update only weakens truncation detection; it doesn't lose
        # the log entry. Don't crash the user's request over it.
        current_app.logger.warning("Could not update audit anchor file")


def _read_anchor():
    try:
        with open(_anchor_path()) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _same(a, b):
    """
    Constant-time comparison. A normal == stops at the first differing
    character, which in some systems leaks timing information an attacker
    can use to guess a valid hash. It's good practice whenever comparing
    MACs, even where that attack isn't realistic.
    """
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def verify_chain():
    """
    Check the whole log. Returns a dict:
        ok:        True if the chain is intact
        count:     number of entries checked
        broken_at: ID of the first bad entry (None if ok, or for truncation)
        reason:    plain-English explanation for the admin page
    """
    key = current_app.config["AUDIT_HMAC_KEY"]

    # Read the anchor BEFORE the rows. If an entry is logged in between,
    # the rows we read will include it, so we never get a false alarm about
    # an anchor pointing at a row we didn't read.
    anchor = _read_anchor()
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id").fetchall()

    expected_prev = GENESIS_HASH
    for row in rows:
        # 1. Does this entry link to the one before it?
        if not _same(row["prev_hash"], expected_prev):
            return {
                "ok": False, "count": len(rows), "broken_at": row["id"],
                "reason": f"Entry #{row['id']} doesn't link to the entry before it. "
                          "An earlier entry was deleted, inserted or altered.",
            }
        # 2. Do this entry's contents still match its hash?
        recomputed = compute_hash(
            key, row["timestamp"], row["user_id"], row["action"],
            row["details"], row["prev_hash"],
        )
        if not _same(recomputed, row["entry_hash"]):
            return {
                "ok": False, "count": len(rows), "broken_at": row["id"],
                "reason": f"Entry #{row['id']} has been altered: its contents "
                          "no longer match its hash.",
            }
        expected_prev = row["entry_hash"]

    # 3. Is the newest entry we know about still there?
    if anchor is not None:
        match = next((r for r in rows if r["id"] == anchor["last_id"]), None)
        if match is None or not _same(match["entry_hash"], anchor["last_hash"]):
            return {
                "ok": False, "count": len(rows), "broken_at": None,
                "reason": f"Entry #{anchor['last_id']}, the newest entry on record, "
                          "is missing. Entries were deleted from the end of the log.",
            }

    return {"ok": True, "count": len(rows), "broken_at": None,
            "reason": f"All {len(rows)} entries verified. The chain is intact."}