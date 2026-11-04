"""
Encrypted records: how health records are protected at rest.

ENVELOPE ENCRYPTION
Every record gets its own random 256-bit AES key (the "data key"). The
record is encrypted with its data key, and the data key is then encrypted
("wrapped") with one master key. The database only ever holds:
  - the encrypted record, and
  - the wrapped data key.
The master key lives outside the database, in instance/record_key (never
committed to Git). So a stolen copy of slainte.sqlite3 is useless on its
own: every record and every data key in it is ciphertext.

Using a separate key per record also means:
  - one leaked data key exposes one record, not all of them, and
  - the master key can be changed ("rotated") by re-wrapping the small
    data keys, without re-encrypting every record.

WHY AES-256-GCM?
GCM is "authenticated encryption": as well as hiding the data
(confidentiality), it adds a tag that detects any change to the ciphertext
(integrity). If even one bit is altered, decryption raises InvalidTag
instead of returning corrupted medical data.

WHY A RANDOM 12-BYTE NONCE EACH TIME?
GCM must never reuse a nonce with the same key; doing so can leak the
plaintext and let attackers forge data. os.urandom() gives a fresh random
nonce for every encryption, so encrypting the same text twice gives two
completely different ciphertexts.

WHY THE RECORD ID AS "ASSOCIATED DATA"?
The record ID isn't secret, but it is included in the tag. Decryption only
succeeds with the same ID, so someone with database access can't move one
patient's encrypted record (or its key) into another record's row.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, the standard nonce size for GCM


# ============================== Master key ==============================

def load_or_create_master_key(instance_path):
    """Return the master key, creating a random one on first run."""
    key_path = os.path.join(instance_path, "record_key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    with open(key_path, "rb") as f:
        return f.read()


# ===================== Low-level encrypt / decrypt ======================

def _encrypt(key, data, associated_data):
    """Encrypt bytes with AES-GCM. Returns nonce + ciphertext (with tag)."""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, associated_data)


def _decrypt(key, blob, associated_data):
    """Reverse _encrypt. Raises InvalidTag if anything was tampered with."""
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def _ad(purpose, record_id):
    # A different label for bodies and keys means a wrapped key can never
    # be mistaken for a record body, or the other way round.
    return f"slainte:{purpose}:{record_id}".encode()


# ======================= What the rest of the app uses ===================

def seal_record(master_key, plaintext, record_id):
    """
    Encrypt a record for storage.
    Returns (encrypted_body, wrapped_key), both bytes for BLOB columns.
    """
    data_key = AESGCM.generate_key(bit_length=256)
    encrypted_body = _encrypt(data_key, plaintext.encode("utf-8"), _ad("body", record_id))
    wrapped_key = _encrypt(master_key, data_key, _ad("key", record_id))
    return encrypted_body, wrapped_key


def open_record(master_key, encrypted_body, wrapped_key, record_id):
    """Decrypt a stored record back to text. Raises InvalidTag if tampered."""
    data_key = _decrypt(master_key, wrapped_key, _ad("key", record_id))
    return _decrypt(data_key, encrypted_body, _ad("body", record_id)).decode("utf-8")
