"""
Two-factor authentication (2FA) with time-based one-time passwords (TOTP).

WHY 2FA?
A password is "something you know". If it's stolen (phishing, malware,
reuse on a breached site), the attacker has everything they need. In the
2021 HSE attack, stolen admin passwords were enough to roam the network.
2FA adds "something you have": a phone that shows a new 6-digit code every
30 seconds. A stolen password alone no longer logs anyone in.

HOW TOTP WORKS (RFC 6238, built on HOTP, RFC 4226)
The server and the phone share one random secret, exchanged once by
scanning a QR code. To make a code, each side independently computes:

    counter = current Unix time // 30         (same on both sides)
    mac     = HMAC-SHA1(secret, counter)      (20 bytes)
    code    = 6 digits taken from the mac     ("dynamic truncation")

Nothing is sent between them at login except the 6 digits the user types.
Because HMAC is one-way, seeing old codes doesn't reveal the secret or
any future code.

WHY HMAC-SHA1, WHEN SHA-1 IS "BROKEN"?
SHA-1's weakness is collisions (finding two inputs with the same hash).
HMAC's security doesn't depend on collision resistance, so HMAC-SHA1 is
still considered secure, and it's the algorithm every authenticator app
supports by default.

WHY IS THE SECRET STORED ENCRYPTED, NOT HASHED?
A password can be stored as a one-way hash because we only ever compare
it. The TOTP secret is different: the server needs the real value to
compute codes. So we encrypt it with AES-256-GCM under a key kept in
instance/ (outside the database). A stolen copy of the database alone
doesn't let an attacker generate anyone's codes.

This file is written with Python's built-in hmac/hashlib modules rather
than a TOTP library, so every step of the algorithm is visible here. It's
checked against the official test values in RFC 6238.
"""

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from urllib.parse import quote

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

from ..db import get_db

ISSUER = "Sláinte Secure"   # shown in the authenticator app
DIGITS = 6
PERIOD = 30                 # seconds each code lasts
SECRET_BYTES = 20           # 160 bits, the size RFC 4226 recommends
NONCE_SIZE = 12             # standard AES-GCM nonce size

# Accept the code from one step before or after the current one, to allow
# for a phone clock that's slightly off or a code typed just as it changed.
# RFC 6238 recommends at most one step of leeway.
WINDOW = 1


# ============================ The TOTP algorithm ============================

def _hotp(secret, counter):
    """One HOTP code (RFC 4226) for a given counter value."""
    # The counter is hashed as an 8-byte big-endian number.
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()

    # Dynamic truncation: the last 4 bits of the MAC pick where to read
    # 4 bytes from; the top bit is dropped to avoid signed-number issues.
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF

    # Keep the last 6 digits, padded with zeros (e.g. 7 -> "000007").
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def time_step(at=None):
    """Which 30-second step a moment falls in (now, by default)."""
    return int(time.time() if at is None else at) // PERIOD


def matching_step(secret, code, at=None):
    """
    Return the time step whose code matches, or None if the code is wrong.

    Returning the step (not just True/False) lets the caller remember it
    and refuse the same code a second time (see verify_user_code).
    """
    code = code.replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None

    current = time_step(at)
    match = None
    for step in range(current - WINDOW, current + WINDOW + 1):
        # compare_digest takes the same time whether the first digit or
        # the last one differs, so response times leak nothing. We also
        # check every step rather than stopping at the first match.
        if hmac.compare_digest(_hotp(secret, step), code):
            match = step
    return match


def new_secret():
    """A fresh random secret from the OS's secure random generator."""
    return secrets.token_bytes(SECRET_BYTES)


def base32_secret(secret):
    """The secret as authenticator apps expect it: Base32, no padding."""
    return base64.b32encode(secret).decode("ascii").rstrip("=")


def provisioning_uri(secret, username):
    """
    The otpauth:// link that the QR code contains. It carries the secret
    and settings to the authenticator app in one scan.
    """
    label = f"{quote(ISSUER)}:{quote(username)}"
    return (
        f"otpauth://totp/{label}?secret={base32_secret(secret)}"
        f"&issuer={quote(ISSUER)}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}"
    )


def qr_code_svg(uri):
    """
    The QR code as an SVG image to put in the page, or None if the qrcode
    package isn't installed (the page then shows the setup key to type in).

    The image is generated on our own server. The secret must never be
    sent to an online QR-code service, which would then know it.
    """
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        return None

    image = qrcode.make(
        uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=10, border=2
    )
    return image.to_string(encoding="unicode")


# ======================== Keeping the secret encrypted =======================

def load_or_create_totp_key(instance_path):
    """
    The AES key that encrypts every user's TOTP secret.

    It has its own key file rather than reusing the session key or the
    records master key (key separation: each key does one job, so a leak
    of one doesn't expose the others).
    """
    key_path = os.path.join(instance_path, "totp_key")
    if not os.path.exists(key_path):
        with open(key_path, "wb") as f:
            f.write(AESGCM.generate_key(bit_length=256))
    with open(key_path, "rb") as f:
        return f.read()


def _associated_data(user_id):
    # Binds each encrypted secret to its owner. Someone with database
    # access can't copy their own (known) secret into another user's row:
    # decryption would fail because the user ID no longer matches.
    return f"slainte:totp:{user_id}".encode()


def _encrypt_secret(secret, user_id):
    nonce = os.urandom(NONCE_SIZE)  # new and random for every encryption
    key = current_app.config["TOTP_ENC_KEY"]
    return nonce + AESGCM(key).encrypt(nonce, secret, _associated_data(user_id))


def _decrypt_secret(blob, user_id):
    """Raises InvalidTag if the stored secret was tampered with or moved."""
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    key = current_app.config["TOTP_ENC_KEY"]
    return AESGCM(key).decrypt(nonce, ciphertext, _associated_data(user_id))


# ========================= What the pages use (database) =====================

def is_enabled(user_id):
    """True if this user has finished setting up 2FA."""
    row = get_db().execute(
        "SELECT enabled FROM two_factor WHERE user_id = ?", (user_id,)
    ).fetchone()
    return row is not None and row["enabled"] == 1


def pending_secret(user_id):
    """
    The secret for a setup that's in progress, creating one if needed.

    The same secret is returned until setup is confirmed, so refreshing
    the setup page doesn't change the QR code after it's been scanned.
    """
    db = get_db()
    row = db.execute(
        "SELECT encrypted_secret FROM two_factor WHERE user_id = ? AND enabled = 0",
        (user_id,),
    ).fetchone()

    if row is not None:
        try:
            return _decrypt_secret(row["encrypted_secret"], user_id)
        except InvalidTag:
            pass  # damaged or tampered with: replace it below

    secret = new_secret()
    db.execute(
        "INSERT INTO two_factor (user_id, encrypted_secret, enabled) VALUES (?, ?, 0) "
        "ON CONFLICT(user_id) DO UPDATE SET encrypted_secret = excluded.encrypted_secret, "
        "enabled = 0, last_used_step = NULL",
        (user_id, _encrypt_secret(secret, user_id)),
    )
    db.commit()
    return secret


def verify_user_code(user_id, code, activate=False):
    """
    Check a 6-digit code for a user. Returns True or False.

    With activate=True, it checks a setup in progress and, if the code is
    right, switches 2FA on. That first code proves the user's phone really
    has the secret before we start demanding codes at login.

    Each code works only once: we store the time step of the last code
    accepted and refuse that step or anything older. Otherwise someone who
    saw a code being typed (or captured it) could reuse it within its 30
    to 90 seconds of validity. This is a "replay attack".
    """
    db = get_db()
    row = db.execute(
        "SELECT encrypted_secret, enabled, last_used_step FROM two_factor WHERE user_id = ?",
        (user_id,),
    ).fetchone()

    if row is None or (row["enabled"] == 1) == activate:
        return False

    try:
        secret = _decrypt_secret(row["encrypted_secret"], user_id)
    except InvalidTag:
        return False

    step = matching_step(secret, code)
    if step is None:
        return False
    if row["last_used_step"] is not None and step <= row["last_used_step"]:
        return False

    db.execute(
        "UPDATE two_factor SET last_used_step = ?, enabled = 1 WHERE user_id = ?",
        (step, user_id),
    )
    db.commit()
    return True


def disable(user_id):
    """Turn 2FA off and delete the secret."""
    db = get_db()
    db.execute("DELETE FROM two_factor WHERE user_id = ?", (user_id,))
    db.commit()
