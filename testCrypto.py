"""testing the cryptography """

import tempfile

from cryptography.exceptions import InvalidTag

from slainte.crypto import create_masterkey, open_record, seal_record

master = create_masterkey(tempfile.mkdtemp())

"""encrypt and decrypt a records"""
body, wrapped = seal_record(master, "Blood type: O+", 1)
assert open_record(master, body, wrapped, 1) == "Blood type: O+"
print("1. Round trip works")
"""prints encrypted version of the records"""
print("Encrypted:", body.hex())
"""prints decrypted version of the records"""
print("Decrypted:", open_record(master, body, wrapped, 1))
"""encrypt again and check that the ciphertext is different"""
body2, wrapped2 = seal_record(master, "Blood type: O+", 1)
assert body != body2 and wrapped != wrapped2
print("2. Same record encrypts differently each time")

"""decrypt and test with incorrect ID"""
try:
    open_record(master, body, wrapped, 2)
    raise AssertionError("should have failed")
except InvalidTag:
    print("3. Wrong record ID rejected")

"""test tampering/altering the ciphertext"""
tampered = body[:-1] + bytes([body[-1] ^ 1])
try:
    open_record(master, tampered, wrapped, 1)
    raise AssertionError("should have failed")
except InvalidTag:
    print("4. Tampering detected")

"""test record with a different master key"""
other_master = create_masterkey(tempfile.mkdtemp())
try:
    open_record(other_master, body, wrapped, 1)
    raise AssertionError("should have failed")
except InvalidTag:
    print("5. Wrong master key rejected")

print("All checks passed.")
