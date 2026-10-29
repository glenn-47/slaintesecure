"""
Password hashing and password rules.

WHY HASH?
We never store passwords. We store a one-way hash, so if the database is
stolen (like the HSE data was) the attacker doesn't get anyone's password.

WHY ARGON2id AND NOT SHA-256?
SHA-256 is designed to be fast, which helps attackers: a graphics card can
try billions of SHA-256 guesses per second. Argon2id is deliberately slow
and needs a lot of memory for every guess, which makes brute-forcing
stolen hashes far more expensive. It won the Password Hashing Competition
in 2015 and is the first choice in OWASP's password storage guidance.

WHAT ABOUT SALT?
Argon2 generates a new random salt for every password automatically, so
two users with the same password get completely different hashes, and
precomputed "rainbow tables" are useless. The salt and settings are saved
inside the hash string itself, which is why the users table has no
separate salt column.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# PasswordHasher() uses the library's recommended Argon2id settings
# (based on RFC 9106): 3 passes over 64 MiB of memory, 4 lanes in parallel.
_hasher = PasswordHasher()

MIN_LENGTH = 12
# A cap stops someone sending a huge "password" to tie up the server.
MAX_LENGTH = 128

# A small sample of the most-used passwords from breach lists. A real
# system would check against a much bigger list (e.g. Have I Been Pwned).
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456789012", "qwertyuiop",
    "iloveyou", "letmein", "welcome123", "admin123456", "passw0rd",
    "1q2w3e4r5t6y", "qwerty123456", "abc123456789", "football123",
}


def hash_password(password):
    """Return the Argon2id hash of a password, ready to store."""
    return _hasher.hash(password)


def verify_password(stored_hash, password):
    """
    Check a password against a stored hash. Returns True or False.

    The library re-hashes the attempt with the salt and settings saved in
    stored_hash, then compares the results in constant time, so the time
    taken doesn't leak how close a guess was.
    """
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash):
    """
    True if the hash was made with older/weaker settings than we use now.
    After a successful login we can quietly upgrade it to the new settings.
    """
    return _hasher.check_needs_rehash(stored_hash)


def password_problems(password, username=""):
    """
    Check a new password against our rules.
    Returns a list of problems; an empty list means it's acceptable.

    The rules follow NIST SP 800-63B: length matters most, and known
    breached passwords are rejected. We don't force "one capital, one
    symbol" rules, because they push people towards predictable
    passwords like "Password1!".
    """
    problems = []

    if len(password) < MIN_LENGTH:
        problems.append(f"Password must be at least {MIN_LENGTH} characters long.")
    if len(password) > MAX_LENGTH:
        problems.append(f"Password must be at most {MAX_LENGTH} characters long.")
    if password.lower() in COMMON_PASSWORDS:
        problems.append("That password is too common. Please choose another.")
    if username and username.lower() in password.lower():
        problems.append("Password must not contain your username.")
    if len(set(password)) < 4:
        problems.append("Password is too repetitive.")

    return problems
