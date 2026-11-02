"""Quick checks for slainte/crypto.py. Run with: python testCrypto.py"""

import tempfile

from cryptography.exceptions import InvalidTag

from slainte.crypto import load_or_create_master_key, open_record, seal_record

master = load_or_create_master_key(tempfile.mkdtemp())

# 1. Round trip: what goes in comes back out.
body, wrapped = seal_record(master, "Blood type: O+", 1)
assert open_record(master, body, wrapped, 1) == "Blood type: O+"
print("1. Round trip works")

# 2. Same text twice gives different ciphertext (random nonce and data key).
body2, wrapped2 = seal_record(master, "Blood type: O+", 1)
assert body != body2 and wrapped != wrapped2
print("2. Same record encrypts differently each time")

# 3. Moving a record to another row (different ID) is rejected.
try:
    open_record(master, body, wrapped, 2)
    raise AssertionError("should have failed")
except InvalidTag:
    print("3. Wrong record ID rejected")

# 4. Changing one byte of the ciphertext is detected.
tampered = body[:-1] + bytes([body[-1] ^ 1])
try:
    open_record(master, tampered, wrapped, 1)
    raise AssertionError("should have failed")
except InvalidTag:
    print("4. Tampering detected")

# 5. A different master key can't unwrap the data key.
other_master = load_or_create_master_key(tempfile.mkdtemp())
try:
    open_record(other_master, body, wrapped, 1)
    raise AssertionError("should have failed")
except InvalidTag:
    print("5. Wrong master key rejected")

print("All checks passed.")
