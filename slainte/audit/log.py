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
import sqlite3
from datetime import datetime, timezone

from flask import current_app

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

        conn.execute(
            "INSERT INTO audit_log "
            "(timestamp, user_id, action, details, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, user_id, action, details, prev_hash, entry_hash),
        )
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()