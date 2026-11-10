"""
Digital signatures on records (non-repudiation).

Ed25519 is a modern elliptic-curve signature scheme: small keys (32 bytes),
fast, and with no random number needed at signing time, which removes a
classic way signatures go wrong (ECDSA leaks the private key if it ever
reuses a random value).

A signature proves two things:
  - integrity: the signed details haven't changed since signing
  - non-repudiation: only the holder of the private key could have made
    it. The private key is encrypted with the doctor's own password, and
    they must re-enter it to sign, so the doctor can't later deny it.

Known limitation (for the report): public keys are trusted from our own
database. Real systems tie public keys to identities with certificates
issued by a certificate authority.
"""

import hashlib
import json

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from flask import current_app

from ..auth.session import current_user
from ..crypto import open_record
from ..db import get_db
from .log import log_event


def record_plaintext(record):
    """The decrypted record exactly as open_record returns it (raises InvalidTag if tampered)."""
    return open_record(
        current_app.config["RECORD_MASTER_KEY"],
        record["encrypted_body"], record["wrapped_key"], record["id"],
    )


def signed_message(record, plaintext):
    """
    The exact bytes that get signed.

    We sign a hash of the plaintext string exactly as decrypted, never
    re-serialised JSON, because re-serialising could change spacing or key
    order and break the signature. The record's ID, patient, author and
    date are included too, so a signature can't be moved onto a different
    record or patient. "slainte-record-v1" labels what the signature is
    for, so it can never be mistaken for a signature on anything else.
    """
    digest = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
    return json.dumps(
        ["slainte-record-v1", record["id"], record["patient_id"],
         record["author_id"], record["created_at"], digest],
        separators=(",", ":"),
    ).encode("utf-8")


def create_key_pair(password):
    """
    New Ed25519 key pair. The private key is encrypted with the doctor's
    password using the library's strongest available password-based
    encryption, so the database alone never reveals it.
    """
    private_key = Ed25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    encrypted = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    return private_key, public_bytes, encrypted


def unlock_private_key(encrypted, password):
    """Decrypt a stored private key. Raises ValueError if the password is wrong."""
    return serialization.load_pem_private_key(encrypted, password=password.encode("utf-8"))


def signature_status(record):
    """
    Check a record's signature. Used by signature_badge.html on every view.
    Returns {"state": "unsigned" | "valid" | "invalid", ...}.
    """
    sig = get_db().execute(
        "SELECT s.*, u.full_name AS signer_name, k.public_key "
        "FROM record_signatures s "
        "JOIN users u ON u.id = s.doctor_id "
        "LEFT JOIN signing_keys k ON k.doctor_id = s.doctor_id "
        "WHERE s.record_id = ?",
        (record["id"],),
    ).fetchone()

    if sig is None:
        return {"state": "unsigned"}

    ok = False
    # The signer must be the record's author, and their key must exist.
    if sig["public_key"] is not None and sig["doctor_id"] == record["author_id"]:
        try:
            Ed25519PublicKey.from_public_bytes(sig["public_key"]).verify(
                sig["signature"], signed_message(record, record_plaintext(record))
            )
            ok = True
        except (InvalidSignature, InvalidTag):
            ok = False

    if not ok:
        user = current_user()
        log_event("integrity_check_failed", user["id"] if user else None,
                  f"signature invalid record_id={record['id']}")
        return {"state": "invalid"}

    return {"state": "valid", "signer_name": sig["signer_name"], "signed_at": sig["signed_at"]}