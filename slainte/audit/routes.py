"""Pages for the integrity and audit section."""

import sqlite3

from cryptography.exceptions import InvalidTag
from flask import abort, flash, redirect, render_template, request, url_for

from ..auth.decorators import role_required
from ..auth.passwords import verify_password
from ..auth.session import current_user
from ..db import get_db
from ..records.access import can_view
from . import bp
from .log import log_event, verify_chain
from .signing import (
    create_key_pair, record_plaintext, signature_status, signed_message,
    unlock_private_key,
)

# Lets any template call signature_status(record), so Filip's view.html
# only needs one {% include %} line and his route doesn't change.
bp.add_app_template_global(signature_status)

PAGE_LIMIT = 200


@bp.route("/")
@role_required("admin")
def log_page():
    """
    The audit log, newest first, with an optional chain check.

    Admins only (least privilege): the log reveals WHO viewed WHICH
    patient's records and when, which is sensitive in itself.
    Verifying is a GET link because it only reads data.
    """
    entries = get_db().execute(
        "SELECT audit_log.*, users.username FROM audit_log "
        "LEFT JOIN users ON users.id = audit_log.user_id "
        "ORDER BY audit_log.id DESC LIMIT ?",
        (PAGE_LIMIT,),
    ).fetchall()
    result = verify_chain() if request.args.get("verify") else None
    return render_template("audit/log.html", entries=entries, result=result, limit=PAGE_LIMIT)


@bp.route("/sign/<int:record_id>", methods=["GET", "POST"])
@role_required("doctor")
def sign_record(record_id):
    """
    The record's author re-enters their password to sign it.

    Re-entering the password is what gives non-repudiation: it unlocks a
    private key only this doctor can unlock, so a stolen session cookie
    alone can't produce a signature.
    """
    user = current_user()
    db = get_db()
    record = db.execute("SELECT * FROM records WHERE id = ?", (record_id,)).fetchone()

    # Same rule as Filip's pages: 404 if missing OR not yours to see.
    if record is None or not can_view(user, record):
        abort(404)
    # A doctor a record was shared with can read it but not sign it.
    if record["author_id"] != user["id"]:
        abort(403)

    back = url_for("records.view_record", record_id=record_id)
    if db.execute("SELECT 1 FROM record_signatures WHERE record_id = ?", (record_id,)).fetchone():
        flash("This record is already signed.", "info")
        return redirect(back)

    if request.method == "GET":
        return render_template("audit/sign.html", record_id=record_id)

    password = request.form.get("password", "")
    password_hash = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
    ).fetchone()["password_hash"]
    key_row = db.execute(
        "SELECT encrypted_private_key FROM signing_keys WHERE doctor_id = ?", (user["id"],)
    ).fetchone()

    # Check the password with Glenn's Argon2 check first, so a typo can
    # never create a key pair locked with the wrong password.
    private_key = None
    if verify_password(password_hash, password):
        if key_row is None:
            private_key, public_bytes, encrypted = create_key_pair(password)
        else:
            try:
                private_key = unlock_private_key(key_row["encrypted_private_key"], password)
            except ValueError:
                private_key = None

    if private_key is None:
        log_event("signature_failed", user["id"], f"record_id={record_id}")
        flash("Incorrect password. The record was not signed.", "error")
        return render_template("audit/sign.html", record_id=record_id), 401

    try:
        signature = private_key.sign(signed_message(record, record_plaintext(record)))
    except InvalidTag:
        flash("This record failed its integrity check, so it can't be signed.", "error")
        return redirect(back)

    try:
        if key_row is None:
            db.execute(
                "INSERT INTO signing_keys (doctor_id, public_key, encrypted_private_key) "
                "VALUES (?, ?, ?)",
                (user["id"], public_bytes, encrypted),
            )
        db.execute(
            "INSERT INTO record_signatures (record_id, doctor_id, signature) VALUES (?, ?, ?)",
            (record_id, user["id"], signature),
        )
        db.commit()
    except sqlite3.IntegrityError:
        # Signed at the same moment in another tab: keep the first one.
        db.rollback()
        flash("This record is already signed.", "info")
        return redirect(back)

    log_event("record_signed", user["id"], f"record_id={record_id}")  # after commit
    flash("Record signed.", "success")
    return redirect(back)