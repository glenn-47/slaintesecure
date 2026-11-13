

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone

from flask import current_app

from ..db import get_db

# prev_hash for the very first entry.
GENESIS_HASH = "0" * 64

# This is all things app can log. A typo like "login_fialed" causes 
# an error instead of just writing entry as i feel that less helpful.
ACTIONS = {
    "login",
    "login_failed",
    "account_locked",
    "logout",
    "two_factor_enabled",
    "two_factor_disabled",
    "record_created",
    "record_viewed",
    "record_signed",
    "signature_failed",
    "integrity_check_failed",
}


def compute_hash(key, timestamp, user_id, action, details, prev_hash):
    """The fields r encoded as a json list rather than glued together as
    strings. this keeps everything seprate so two things never given same hash
    """

    message = json.dumps(
        [timestamp, user_id, action, details, prev_hash],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _connect():
    """
    A seprate connection just for writing to the log.
    log_event() controls when  transaction starts and ends.
    """
    conn = sqlite3.connect(
        current_app.config["DATABASE"], isolation_level=None, timeout=10
    )
    conn.row_factory = sqlite3.Row
    return conn


def log_event(action, user_id=None, details=""):
    """adds 1 entry to the end of the audit log chain."""
    if action not in ACTIONS:
        raise ValueError(f"Unknown audit action: {action!r}")

    # this stops false tampering alerts
    user_id = int(user_id) if user_id is not None else None
    details = str(details)

    key = current_app.config["AUDIT_HMAC_KEY"]
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE") #takes the database write lock b4 we read the
                                        #last hash.

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
        # save anchor after commit 
        _write_anchor(cursor.lastrowid, entry_hash)

    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


# after `flask --app run reset-db`, also delete the instance of audit anchor

ANCHOR_FILENAME = "audit_anchor.json"


def _anchor_path():
    return os.path.join(current_app.instance_path, ANCHOR_FILENAME)


def _write_anchor(last_id, last_hash):
    """Record the newest entry. Written atomically, so it's never half-written."""
    path = _anchor_path()
    # writes to a uniquely named temp file
    tmp = f"{path}.{secrets.token_hex(4)}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"last_id": last_id, "last_hash": last_hash}, f)
        os.replace(tmp, path) #replaces temp file
    except OSError:
        current_app.logger.warning("Could not update audit anchor file")


def _read_anchor():
    try:
        with open(_anchor_path()) as f:
            return json.load(f)
    except FileNotFoundError:
        return None


# verification 


def _same(a, b):
    return hmac.compare_digest(str(a).encode(), str(b).encode())


def verify_chain():
    """
    returns info about chain.
    Check the whole log. Returns a dict:
    """
    key = current_app.config["AUDIT_HMAC_KEY"]


    anchor = _read_anchor()
    rows = get_db().execute("SELECT * FROM audit_log ORDER BY id").fetchall()

    expected_prev = GENESIS_HASH
    for row in rows:
        #does entry link to the one before it?
        if not _same(row["prev_hash"], expected_prev):
            return {
                "ok": False, "count": len(rows), "broken_at": row["id"],
                "reason": f"Entry #{row['id']} doesn't link to the entry before it. "
                          "An earlier entry was deleted, inserted or altered.",
            }
        #checks if entry still matches its hash
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

    #checks if newest entry is present
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