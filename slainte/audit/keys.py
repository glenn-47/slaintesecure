
import os
import secrets

keyFileName = "audit_hmac.key"
keyBytes = 32  # 256 bits, matching SHA-256's output size, as RFC 2104 recommends


def load_or_create_audit_key(instance_path):
    """Return the audit HMAC key"""
    theKeyPath = os.path.join(instance_path, keyFileName)

    if not os.path.exists(theKeyPath):
        # O_EXCL: only make file if it dont exist. dont overwrite 
        # 0o600: only the owner can read it (ignored on Windows).
        fd = os.open(theKeyPath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            #using secrets instead of random as secrets is more secure
            #          \/
            
            f.write(secrets.token_bytes(keyBytes))

    with open(theKeyPath, "rb") as f:
        key = f.read()


    # Fails at startup if file damaged. 
    # Worng length key still works but looks different and tampered
    if len(key) != keyBytes:
        raise RuntimeError(
            f"{theKeyPath} should be {keyBytes} bytes but is {len(key)}. "
            "Restore it from backup rather than deleting it."
        )
    return key