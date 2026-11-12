"""
Secret key for the audit log's HMAC chain.

Why a secret key at all? If each log entry were hashed with plain SHA-256,
everything that goes into the hash would be sitting in the database. An
attacker with database access could edit an old entry, recompute that
hash and every hash after it, and the chain would still verify. HMAC-SHA256
mixes a secret key into every hash, so producing a valid hash needs the
key. The key lives in the instance/ folder (gitignored, outside the
database), so stealing or editing slainte.sqlite3 alone isn't enough to
forge the log.

Why not reuse RECORDMASTERKEY or SECRET_KEY? Key separation: each key
does one job, so a leak or misuse of one doesn't weaken the others.

IMPORTANT: if this file is lost or replaced, every existing log entry will
fail verification, because the old hashes were made with the old key.
"""

import os
import secrets

KEY_FILENAME = "audit_hmac.key"
KEY_BYTES = 32  # 256 bits, matching SHA-256's output size, as RFC 2104 recommends


def load_or_create_audit_key(instance_path):
    """Return the audit HMAC key, generating it on first run."""
    key_path = os.path.join(instance_path, KEY_FILENAME)

    if not os.path.exists(key_path):
        # O_EXCL: if the file somehow appears between the check above and
        # this line, fail rather than overwrite it. Overwriting the key
        # would silently invalidate the whole log.
        # 0o600: only the owner can read it (ignored on Windows).
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            # `secrets` uses the OS's cryptographically secure random
            # generator; `random` is predictable and must never be used for keys.
            f.write(secrets.token_bytes(KEY_BYTES))

    with open(key_path, "rb") as f:
        key = f.read()

    # Fail loudly at startup if the file is damaged. A wrong-length key
    # would still "work", but every hash would come out different and the
    # whole log would look tampered with.
    if len(key) != KEY_BYTES:
        raise RuntimeError(
            f"{key_path} should be {KEY_BYTES} bytes but is {len(key)}. "
            "Restore it from backup rather than deleting it."
        )
    return key