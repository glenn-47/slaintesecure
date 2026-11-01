import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_or_create_record_key(instance_path):
    """Same idea as the secret_key in __init__.py: random, kept in instance/."""
    key_path = os.path.join(instance_path, "record_key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    with open(key_path, "rb") as f:
        return f.read()

def encrypt_record(key, plaintext, record_id):
    nonce = os.urandom(12)  # must be new and random for every encryption
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), str(record_id).encode())
    return nonce + ciphertext  # store the nonce with the ciphertext

def decrypt_record(key, blob, record_id):
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, str(record_id).encode()).decode()