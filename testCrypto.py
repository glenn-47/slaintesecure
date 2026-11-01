import tempfile
from slainte.crypto import load_or_create_record_key, encrypt_record, decrypt_record

key = load_or_create_record_key(tempfile.mkdtemp())
blob = encrypt_record(key, "Blood type: O+", 1)
print("Encrypted:", blob.hex())
print("Decrypted:", decrypt_record(key, blob, 1))

try:
    decrypt_record(key, blob, 2)
except Exception as e:
    print("Wrong record id rejected:", type(e).__name__)