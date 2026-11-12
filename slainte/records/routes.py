"""Web pages for records: list, create (doctors), view, and share (patients)."""

import json
import re

from cryptography.exceptions import InvalidTag #used to catch failures in integrity checks when records get decrypted. used by decrypt.record() function
from flask import abort, current_app, flash, redirect, render_template, request, url_for #aborts when 404 error happens, get_records() function uses it for example

from ..auth import current_user, role_required #checks roles of the user and if the user is logged in, mainly used by routes to check if the user has the correct role to access records.
from ..crypto import open_record, seal_record #is used to encrypt records and decrypt records 
from ..db import get_db #gets the dataabse connected and allows queries to the database to be made, used by viewed_records() function for example.
from ..audit.log import log_event #gets the logs and records whatever happens in the app by the user and saves them in the database, used by view_record() function for example
from . import bp #used to register the blueprints for records, all funtions use this import.
from .access import can_view #checks if the user has permission to view the records

TITLE = 200 # max length of record title
CONTENT = 10_000 #max length of record content


ID_PATTERN = re.compile(r"[0-9]{1,18}") #matches the records id patterns so the records get delivered to the correct user, parse_id() function uses it for example.


""" Helpers for parsing and validating record IDs. """
def parse_id(value):
    """Turn a form into an account ID, else return none"""
    if value is None or not ID_PATTERN.fullmatch(value):
        return None
    return int(value)
 
def masterkey():
    """ masterkey for encrypted records"""

    return current_app.config["RECORDMASTERKEY"]

def decrypt(record):
    """ Decrypt records"""

    try:
        text = open_record(
            masterkey(), record["encrypted_body"], record["wrapped_key"], record["id"]
        )
    except InvalidTag:
        current_app.logger.warning("Record %s failed its integrity check", record["id"])
        log_event("integrity_check_failed", current_user()["id"], f"record_id={record['id']}")
        return None
    return json.loads(text)

def patient_query():
    """ Get a patient from the query string"""

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

def viewed_records(record_id):
    """Get records for the user, or else none if the user has no records or the user is not logged in."""
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



"""LIST OF RECORDS"""
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
        patient = patient_query()
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
        body = decrypt(row)
        records.append({
            "id": row["id"],
            "title": body["title"] if body else None,
            "patient_name": row["patient_name"],
            "author_name": row["author_name"],
            "created_at": row["created_at"],
        })

    return render_template("records/list.html", records=records, patient=patient)


"""CREATE RECORDS"""
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
        patient = patient_query()
        form = {"patient_id": str(patient["id"])} if patient else {}
        return render_template("records/new.html", patients=patients, form=form)

    form = request.form
    title = form.get("title", "").strip()
    content = form.get("content", "").strip()
    patient_id = form.get("patient_id", "")

    errors = []
    if not 1 <= len(title) <= TITLE:
        errors.append(f"Please enter a title (up to {TITLE} characters).")
    if not 1 <= len(content) <= CONTENT:
        errors.append(f"Please enter the record (up to {CONTENT:,} characters).")

    
    patient = None
    patient_id = parse_id(patient_id)
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
    encrypted_body, wrapped_key = seal_record(masterkey(), plaintext, record_id)

    db.execute(
        "UPDATE records SET encrypted_body = ?, wrapped_key = ? WHERE id = ?",
        (encrypted_body, wrapped_key, record_id),
    )
    db.commit()
    log_event("record_created", current_user()["id"], f"record_id={record_id} patient_id={patient['id']}")

    flash("Record saved and encrypted.", "success")
    return redirect(url_for("records.view_record", record_id=record_id))



"""VIEW RECORDS"""
@bp.route("/<int:record_id>")
@role_required("patient", "doctor")
def view_record(record_id):
    """Show one record, if the logged-in user is allowed to see it."""
    record = viewed_records(record_id)
    body = decrypt(record)

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
        shared_with = doctors_shared(record)
        can_share_with = doctors_not_shared(record)

    return render_template(
        "records/view.html",
        record=record,
        body=body,
        shared_with=shared_with,
        can_share_with=can_share_with,
    )


"""SHARING"""


def get_records(record_id):
    """get recors that belong to the logged in patient, or recieve 404 error."""
    record = get_db().execute(
        "SELECT * FROM records WHERE id = ? AND patient_id = ?",
        (record_id, current_user()["id"]),
    ).fetchone()
    if record is None:
        abort(404)
    return record


def doctors_shared(record):
    return get_db().execute(
        "SELECT u.id, u.full_name, u.username, s.granted_at "
        "FROM record_shares s JOIN users u ON u.id = s.doctor_id "
        "WHERE s.record_id = ? ORDER BY u.full_name",
        (record["id"],),
    ).fetchall()


def doctors_not_shared(record):
    """get doctors that didnt share records with patients yet."""
    return get_db().execute(
        "SELECT id, full_name, username FROM users "
        "WHERE role = 'doctor' AND id != ? "
        "  AND id NOT IN (SELECT doctor_id FROM record_shares WHERE record_id = ?) "
        "ORDER BY full_name",
        (record["author_id"], record["id"]),
    ).fetchall()


def doctor_id():
    """
    read the id of the doctor from the form, and return the doctor if the doctor exists
    in the database, or else it returns None.

    
    """
    doctor_id = parse_id(request.form.get("doctor_id"))
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
    """Patient gives access to a record to a doctor"""
    record = get_records(record_id)
    doctor = doctor_id()

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
    """patient revokes the access to a doctor from reading the patients records"""
    record = get_records(record_id)
    doctor = doctor_id()

    if doctor is not None:
        db = get_db()
        db.execute(
            "DELETE FROM record_shares WHERE record_id = ? AND doctor_id = ?",
            (record["id"], doctor["id"]),
        )
        db.commit()
        flash(f"{doctor['full_name']} can no longer see this record.", "success")

    return redirect(url_for("records.view_record", record_id=record["id"]))
