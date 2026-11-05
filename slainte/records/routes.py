"""Web pages for records: list, create (doctors) and view."""

import json

from cryptography.exceptions import InvalidTag
from flask import abort, current_app, flash, redirect, render_template, request, url_for

from ..auth import current_user, role_required
from ..crypto import open_record, seal_record
from ..db import get_db
from ..audit.log import log_event
from . import bp
from .access import can_view

TITLE_MAX = 200
CONTENT_MAX = 10_000


# ================================ Helpers ================================

def _master_key():
    return current_app.config["RECORD_MASTER_KEY"]


def _decrypt(record):
    """
    Decrypt a record row into a dict with "title" and "content".

    Returns None if decryption fails. GCM only fails if the ciphertext,
    the wrapped key or the record ID has been changed, i.e. someone
    tampered with the database, so we refuse to show anything rather
    than display data we can't trust.
    """
    try:
        text = open_record(
            _master_key(), record["encrypted_body"], record["wrapped_key"], record["id"]
        )
    except InvalidTag:
        current_app.logger.warning("Record %s failed its integrity check", record["id"])
        log_event("integrity_check_failed", current_user()["id"], f"record_id={record['id']}")
        return None
    return json.loads(text)


def _get_viewable_record_or_404(record_id):
    """
    Load a record the current user is allowed to see, or stop with 404.

    We answer 404 Not Found, not 403 Forbidden, when the user isn't
    allowed in. A 403 would confirm "this record exists, you just can't
    see it", which lets someone count records or probe IDs. With 404,
    "not yours" and "doesn't exist" look exactly the same.
    """
    record = get_db().execute(
        "SELECT r.*, p.full_name AS patient_name, a.full_name AS author_name "
        "FROM records r "
        "JOIN users p ON p.id = r.patient_id "
        "JOIN users a ON a.id = r.author_id "
        "WHERE r.id = ?",
        (record_id,),
    ).fetchone()

    if not can_view(current_user(), record):
        abort(404)
    return record


# ============================== Record list ==============================

@bp.route("/")
@role_required("patient", "doctor")
def list_records():
    """
    Patients see their own records. Doctors see records they wrote, plus
    any that patients have shared with them.

    The SQL only ever selects rows the user is allowed to see, and each
    one is checked with can_view() as well, so the list and the record
    page can never disagree about access.
    """
    user = current_user()
    db = get_db()

    if user["role"] == "patient":
        rows = db.execute(
            "SELECT r.*, p.full_name AS patient_name, a.full_name AS author_name "
            "FROM records r "
            "JOIN users p ON p.id = r.patient_id "
            "JOIN users a ON a.id = r.author_id "
            "WHERE r.patient_id = ? ORDER BY r.created_at DESC, r.id DESC",
            (user["id"],),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT r.*, p.full_name AS patient_name, a.full_name AS author_name "
            "FROM records r "
            "JOIN users p ON p.id = r.patient_id "
            "JOIN users a ON a.id = r.author_id "
            "WHERE r.author_id = ? "
            "   OR r.id IN (SELECT record_id FROM record_shares WHERE doctor_id = ?) "
            "ORDER BY r.created_at DESC, r.id DESC",
            (user["id"], user["id"]),
        ).fetchall()

    records = []
    for row in rows:
        if not can_view(user, row):
            continue
        body = _decrypt(row)
        records.append({
            "id": row["id"],
            "title": body["title"] if body else None,
            "patient_name": row["patient_name"],
            "author_name": row["author_name"],
            "created_at": row["created_at"],
        })

    return render_template("records/list.html", records=records)


# ============================= Create record =============================

@bp.route("/new", methods=["GET", "POST"])
@role_required("doctor")
def new_record():
    """
    A doctor writes a new record for a patient.

    The title and content are encrypted together, so nothing about the
    record's medical content (not even "HIV test results" as a title) is
    stored readable in the database.
    """
    db = get_db()
    patients = db.execute(
        "SELECT id, full_name, username FROM users WHERE role = 'patient' ORDER BY full_name"
    ).fetchall()

    if request.method == "GET":
        return render_template("records/new.html", patients=patients, form={})

    form = request.form
    title = form.get("title", "").strip()
    content = form.get("content", "").strip()
    patient_id = form.get("patient_id", "")

    errors = []
    if not 1 <= len(title) <= TITLE_MAX:
        errors.append(f"Please enter a title (up to {TITLE_MAX} characters).")
    if not 1 <= len(content) <= CONTENT_MAX:
        errors.append(f"Please enter the record (up to {CONTENT_MAX:,} characters).")

    # Never trust the patient_id from the form: someone could edit the
    # page and send any number. Check it really is a patient account.
    patient = None
    if patient_id.isdigit():
        patient = db.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'patient'", (int(patient_id),)
        ).fetchone()
    if patient is None:
        errors.append("Please choose a patient.")

    if errors:
        for error in errors:
            flash(error, "error")
        return render_template("records/new.html", patients=patients, form=form), 400

    # The record ID is bound into the encryption (see crypto.py), but
    # SQLite only gives us the ID once the row exists. So we insert a row
    # with empty placeholders, encrypt using its new ID, then fill it in.
    # Both steps happen before commit(), so if anything fails nothing is
    # saved and an unencrypted or half-written record can never exist.
    cursor = db.execute(
        "INSERT INTO records (patient_id, author_id, encrypted_body, wrapped_key) "
        "VALUES (?, ?, X'', X'')",
        (patient["id"], current_user()["id"]),
    )
    record_id = cursor.lastrowid

    plaintext = json.dumps({"title": title, "content": content})
    encrypted_body, wrapped_key = seal_record(_master_key(), plaintext, record_id)

    db.execute(
        "UPDATE records SET encrypted_body = ?, wrapped_key = ? WHERE id = ?",
        (encrypted_body, wrapped_key, record_id),
    )
    db.commit()
    log_event("record_created", current_user()["id"], f"record_id={record_id} patient_id={patient['id']}")

    flash("Record saved and encrypted.", "success")
    return redirect(url_for("records.view_record", record_id=record_id))


# ============================== View record ==============================

@bp.route("/<int:record_id>")
@role_required("patient", "doctor")
def view_record(record_id):
    """Show one record, if the logged-in user is allowed to see it."""
    record = _get_viewable_record_or_404(record_id)
    body = _decrypt(record)

    if body is None:
        flash(
            "This record failed its integrity check and may have been tampered "
            "with, so it can't be shown.",
            "error",
        )
    if body is not None:                                                    # NEW
        log_event("record_viewed", current_user()["id"], f"record_id={record_id}")  # NEW
        
    return render_template("records/view.html", record=record, body=body)
