# Sláinte Secure

A secure health records app for our Security Fundamentals and Development CA. We picked use case 7, Secure Healthcare Records. Patients and doctors can store and share records, and cryptography keeps them private and protected.

## Features

- Patients can sign up for an account
- Passwords are hashed with Argon2id (with a random salt for each one), so they're never stored as plain text
- Logging in and out
- Accounts lock for 15 minutes after 5 wrong passwords
- All forms are protected against CSRF
- Doctor and admin accounts (made from the terminal)
- Pages can be locked to certain roles, e.g. only doctors can see the patient list
- You get logged out after 15 minutes of doing nothing, or 8 hours in total
- Doctors can write health records for patients, which are encrypted before they're saved
- Patients can see their own records, and share each one with specific doctors (and take access away again)
- Two-factor authentication: anyone can turn it on, and then logging in also needs a 6-digit code from an authenticator app

## Team

| Name | Part |
|---|---|
| Glenn | Accounts and access: sign up, login, password hashing, roles |
| Filip | Encrypted records: encrypting records and sharing them securely |
| Andrew | Integrity and audit: signing records and a tamper-proof audit log |

## Built with

- Python 3.10 or newer
- Flask for the web pages
- SQLite for the database
- argon2-cffi for password hashing
- cryptography for encrypting records (AES-256-GCM)
- qrcode for the two-factor setup QR code

## Getting it running

### 1. Clone the repo

```bash
git clone https://github.com/glenn-47/slaintesecure.git
cd slaintesecure
```

### 2. Set up a virtual environment

Run this inside the project folder. The `.venv` folder is ignored by Git.

**Mac / Linux**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows**
```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

`(.venv)` should show at the start of your terminal line. You'll need to activate it again whenever you open a new terminal.

### 3. Install the packages

```bash
pip install -r requirements.txt
```

### 4. Run it

```bash
python run.py
```

Go to http://127.0.0.1:5000 in browser. Ctrl+C stops it.

## Useful commands

Wipe the database and start fresh:

```bash
flask --app run reset-db
```

Create a doctor or admin account (people can only sign up as patients on the website):

```bash
flask --app run create-user --role doctor
flask --app run create-user --role admin
```

It asks for a username, full name and password.

Turn off two-factor authentication for someone who lost their phone:

```bash
flask --app run reset-2fa USERNAME
```

## Two-factor authentication

Anyone can turn this on from the **Security** link at the top of the page. After
that, logging in needs the password and a 6-digit code from an authenticator app
(Google Authenticator, Microsoft Authenticator etc), so a stolen password
isn't enough on its own.

- **TOTP (RFC 6238):** the app and the server share a secret. Each works out the
  code from HMAC-SHA1 of the secret and the current 30-second time step. The code
  is written out in `slainte/auth/totp.py` using Python's built-in `hmac` module
  and checked against the test values in the RFC.
- **The secret is encrypted, not hashed.** The server needs the real secret to work
  out codes, so it's stored with AES-256-GCM. The key is in `instance/totp_key`,
  which is never committed.
- **Each code only works once**, so a code someone sees or captures can't be reused.
- **Wrong codes count towards the lockout**, the same as wrong passwords, so the
  million possible codes can't just be tried one by one.
- **Turning it off needs the password again.**

## Encrypted records

Every record is encrypted before it goes in the database, so the database file
on its own only holds unreadable ciphertext.

- **Envelope encryption:** each record gets its own random AES-256 key. The record
  is encrypted with that key, and the key is then encrypted ("wrapped") with a
  master key. Only the wrapped key is stored in the database. The master key lives
  in `instance/record_key`, which is never committed.
- **AES-256-GCM:** authenticated encryption, so it hides the record *and* detects
  any change to it. A tampered record fails its integrity check instead of showing
  corrupted data.
- **A fresh random nonce every time**, so the same record never encrypts the same
  way twice.
- **The record ID is bound into the encryption** (associated data), so an encrypted
  record can't be moved into another record's row.
- **The title is encrypted too**, since a title alone can give away medical details.

Who can read a record is decided in one place, `can_view()` in
`slainte/records/access.py`:

- the patient it's about,
- the doctor who wrote it,
- doctors the patient has shared it with.

Nobody else can, including admins. Checking the record itself, not just the role,
stops one doctor reading another doctor's patients by changing the number in the
URL (IDOR). Anyone without access gets "Not Found", so they can't tell whether a
record exists.

Only the patient can share or revoke a record. Revoking works immediately. If you
use the records in your own part:

```python
from slainte.records import can_view

can_view(user, record)   # True if this user may read the record
```

## Project layout

```
slaintesecure/
├── run.py                  # starts the app
├── requirements.txt        # packages needed
└── slainte/
    ├── __init__.py         # sets up the app
    ├── db.py               # database connection
    ├── schema.sql          # database tables
    ├── csrf.py             # CSRF protection
    ├── crypto.py           # record encryption (AES-256-GCM, envelope encryption)
    ├── auth/               # accounts and login
    │   ├── passwords.py    # Argon2 hashing and password rules
    │   ├── routes.py       # sign up, login, logout, patient list
    │   ├── totp.py         # two-factor codes (TOTP) and the encrypted secret
    │   ├── two_factor.py   # two-factor pages: setup, login step, turn off
    │   ├── session.py      # current_user() and session timeouts
    │   ├── decorators.py   # login_required and role_required
    │   └── cli.py          # create-user and reset-2fa commands
    ├── records/            # encrypted records
    │   ├── routes.py       # list, create, view, share and revoke
    │   └── access.py       # can_view(): who may read a record
    ├── templates/          # HTML pages
    └── static/             # CSS
```
