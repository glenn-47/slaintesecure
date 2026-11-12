"""
Encrypted records: how mediacal records are protected from unnauthorized users

ENVELOPE ENCRYPTION
The records are encyrpted in a Envelope Encryption, this encrypts the records with
randomly generated 256-bit AES keys which then the key gets encrypted again with the 
master key which is stored in the instance/record_key file.
Records then get double protected, even if the attacker will get access to the daatabase,
the attacker will not be able to decrypt the records without the master key.


WHY AES-256-GCM?
The reason why we chsoe AES-356-GCM is because of how protective, modern and 
how fast it is. AES-GCM is a (AEAD) Authenticated Encryption with Associated Data,
which means the data cannot be altered without the decryption not passing.
This is a huge benefit for medical records because the records are not able to be altered 
with, even when you have access to the database.


WHY A RANDOM 12-BYTE NONCE EACH TIME?
The reason why we use a random 12-byte nonce is because it is firstly a standard
for AES-GCM, and secondly, its a important security measure because it cannot use
the same nonce twice with teh same key or else the encryption will break.

WHY THE RECORD ID AS "ASSOCIATED DATA"?
The reason why Record ID is used as associated data is because it is a unique
identifier for each record and its crucial for the encryption to know where
the record belongs to and to decrypt it properly.
"""

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bits, the standard nonce size for GCM



def load_or_create_master_key(instance_path):
    """Get/create the master key"""
    key_path = os.path.join(instance_path, "record_key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    with open(key_path, "rb") as f:
        return f.read()


def _encrypt(key, data, associated_data):
    """Encrypt the data"""
    nonce = os.urandom(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, associated_data)


def _decrypt(key, blob, associated_data):
    """Decrypt the data"""
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, associated_data)


def _ad(purpose, record_id):
    """Generate associated data for encryption/decryption"""
    return f"slainte:{purpose}:{record_id}".encode()



def seal_record(master_key, plaintext, record_id):
    """
    Encrypt a record to store in the database
    """
    data_key = AESGCM.generate_key(bit_length=256)
    encrypted_body = _encrypt(data_key, plaintext.encode("utf-8"), _ad("body", record_id))
    wrapped_key = _encrypt(master_key, data_key, _ad("key", record_id))
    return encrypted_body, wrapped_key


def open_record(master_key, encrypted_body, wrapped_key, record_id):
    """Decrypt a stored record back to plaintext"""
    data_key = _decrypt(master_key, wrapped_key, _ad("key", record_id))
    return _decrypt(data_key, encrypted_body, _ad("body", record_id)).decode("utf-8")
