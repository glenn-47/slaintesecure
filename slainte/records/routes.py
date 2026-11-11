"""Web pages for records: list, create (doctors), view, and share (patients)."""

import json
import re

from cryptography.exceptions import InvalidTag
from flask import abort, current_app, flash, redirect, render_template, request, url_for

from ..auth import current_user, role_required
from ..crypto import open_record, seal_record
from ..db import get_db
from ..audit.log import log_event
from . import bp
from .access import can_view

TITLE_MAX = 200 # max length of record title
CONTENT_MAX = 10_000 #max length of record content


ID_PATTERN = re.compile(r"[0-9]{1,18}")


""" Helpers for parsing and validating record IDs. """
def _parse_id(value):
    """Turn a form into an account ID, else return none"""
    if value is None or not ID_PATTERN.fullmatch(value):
        return None
    return int(value)
 
""" masterkey for encrypted records"""
def _master_key():
    return current_app.config["RECORD_MASTER_KEY"]

""" Decrypt records"""
def _decrypt(record):

    try:
        text = open_record(
            _master_key(), record["encrypted_body"], record["wrapped_key"], record["id"]
        )
    except InvalidTag:
        current_app.logger.warning("Record %s failed its integrity check", record["id"])
        log_event("integrity_check_failed", current_user()["id"], f"record_id={record['id']}")
        return None
    return json.loads(text)

""" Get a patient from the query string"""
def _patient_from_query():
        
    username = request.args.get("patient", "").strip()
    if not username:
        return None
    patient = get_db().execute(
        "SELECT id, username, full_name FROM users WHERE username = ? AND role = 'patient'",
        (username,),
    ).fetchone()
    if patient is None:
        abort(404)
    return patient

"""Get records for the user, or else none if the user has no records or the user is not logged in."""
def _get_viewable_record_or_404(record_id):
 
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
    Patients can only see their own records that were written by doctors.
    Doctors can see records that only they wrote, or records that the patient
    shared to the doctor.

    Doctor can filter a patients records by clicking on a patients name
    in the list of records, itll then show the doctor the patients records
    or have the ability to create a new record for the patient.

    Using SQL, the user can only see recrods that they are able to view.
    """
    user = current_user()
    db = get_db()
    patient = None

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
        patient = _patient_from_query()
        sql = (
            "SELECT r.*, p.full_name AS patient_name, a.full_name AS author_name "
            "FROM records r "
            "JOIN users p ON p.id = r.patient_id "
            "JOIN users a ON a.id = r.author_id "
            "WHERE (r.author_id = ? "
            "   OR r.id IN (SELECT record_id FROM record_shares WHERE doctor_id = ?)) "
        )
        params = [user["id"], user["id"]]
        if patient is not None:
            sql += "AND r.patient_id = ? "
            params.append(patient["id"])
        sql += "ORDER BY r.created_at DESC, r.id DESC"
        rows = db.execute(sql, params).fetchall()

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

    return render_template("records/list.html", records=records, patient=patient)


# ============================= Create record =============================

@bp.route("/new", methods=["GET", "POST"])
@role_required("doctor")
def new_record():
    """
    The doctor can crete a new record for a patient
    and the patient will be able to recieve and see the record in their list
    of records.
    """
    db = get_db()
    patients = db.execute(
        "SELECT id, full_name, username FROM users WHERE role = 'patient' ORDER BY full_name"
    ).fetchall()

    if request.method == "GET":
       #pick a patient in the dropdown.
        patient = _patient_from_query()
        form = {"patient_id": str(patient["id"])} if patient else {}
        return render_template("records/new.html", patients=patients, form=form)

    form = request.form
    title = form.get("title", "").strip()
    content = form.get("content", "").strip()
    patient_id = form.get("patient_id", "")

    errors = []
    if not 1 <= len(title) <= TITLE_MAX:
        errors.append(f"Please enter a title (up to {TITLE_MAX} characters).")
    if not 1 <= len(content) <= CONTENT_MAX:
        errors.append(f"Please enter the record (up to {CONTENT_MAX:,} characters).")

    
    patient = None
    patient_id = _parse_id(patient_id)
    if patient_id is not None:
        patient = db.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'patient'", (patient_id,)
        ).fetchone()
    if patient is None:
        errors.append("Please choose a patient.")

    if errors:
        for error in errors:
            flash(error, "error")
        return render_template("records/new.html", patients=patients, form=form), 400
    """The record is created and encrypted and then stored in the database."""
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

    if body is not None:
        log_event("record_viewed", current_user()["id"], f"record_id={record_id}")

    """ Patients can see who can see their records"""
    shared_with, can_share_with = [], []
    if current_user()["role"] == "patient":
        shared_with = _doctors_shared_with(record)
        can_share_with = _doctors_not_yet_shared_with(record)

    return render_template(
        "records/view.html",
        record=record,
        body=body,
        shared_with=shared_with,
        can_share_with=can_share_with,
    )


# ================================ Sharing ================================


def _get_own_record_or_404(record_id):
    """Load a record that belongs to the logged-in patient, or stop with 404."""
    record = get_db().execute(
        "SELECT * FROM records WHERE id = ? AND patient_id = ?",
        (record_id, current_user()["id"]),
    ).fetchone()
    if record is None:
        abort(404)
    return record


def _doctors_shared_with(record):
    return get_db().execute(
        "SELECT u.id, u.full_name, u.username, s.granted_at "
        "FROM record_shares s JOIN users u ON u.id = s.doctor_id "
        "WHERE s.record_id = ? ORDER BY u.full_name",
        (record["id"],),
    ).fetchall()


def _doctors_not_yet_shared_with(record):
    """Doctors the patient could share with: not the author, not already shared."""
    return get_db().execute(
        "SELECT id, full_name, username FROM users "
        "WHERE role = 'doctor' AND id != ? "
        "  AND id NOT IN (SELECT doctor_id FROM record_shares WHERE record_id = ?) "
        "ORDER BY full_name",
        (record["author_id"], record["id"]),
    ).fetchall()


def _doctor_id_from_form():
    """
    Read doctor_id from the form and check it's a real doctor account.

    Never trust form values: someone could edit the page and send the ID
    of a patient or admin, so we check the role in the database.
    """
    doctor_id = _parse_id(request.form.get("doctor_id"))
    if doctor_id is None:
        return None
    doctor = get_db().execute(
        "SELECT id, full_name FROM users WHERE id = ? AND role = 'doctor'",
        (doctor_id,),
    ).fetchone()
    return doctor


@bp.route("/<int:record_id>/share", methods=["POST"])
@role_required("patient")
def share_record(record_id):
    """A patient gives one specific doctor access to one of their records."""
    record = _get_own_record_or_404(record_id)
    doctor = _doctor_id_from_form()

    if doctor is None:
        flash("Please choose a doctor.", "error")
    elif doctor["id"] == record["author_id"]:
        flash(f"{doctor['full_name']} wrote this record, so they already have access.", "error")
    else:
        db = get_db()
 
        db.execute(
            "INSERT OR IGNORE INTO record_shares (record_id, doctor_id) VALUES (?, ?)",
            (record["id"], doctor["id"]),
        )
        db.commit()
        flash(f"Shared with {doctor['full_name']}.", "success")

    return redirect(url_for("records.view_record", record_id=record["id"]))


@bp.route("/<int:record_id>/revoke", methods=["POST"])
@role_required("patient")
def revoke_share(record_id):
    """A patient takes a doctor's access away again. Takes effect immediately."""
    record = _get_own_record_or_404(record_id)
    doctor = _doctor_id_from_form()

    if doctor is not None:
        db = get_db()
        db.execute(
            "DELETE FROM record_shares WHERE record_id = ? AND doctor_id = ?",
            (record["id"], doctor["id"]),
        )
        db.commit()
        flash(f"{doctor['full_name']} can no longer see this record.", "success")

    return redirect(url_for("records.view_record", record_id=record["id"]))
