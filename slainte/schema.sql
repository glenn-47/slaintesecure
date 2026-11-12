-- Sláinte Secure database schema.
--
-- "IF NOT EXISTS" means this file can run every time the app starts
-- without wiping data: tables are only created if they're missing.
-- Each part of the project adds its own tables to this file.


-- ===================== Accounts and access =====================

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,

    -- COLLATE NOCASE makes "Glenn" and "glenn" count as the same
    -- username, so nobody can register a look-alike account.
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    full_name       TEXT    NOT NULL,

    -- The Argon2id hash of the password, never the password itself.
    -- There's no separate salt column: Argon2 stores the random salt
    -- and its settings inside this one string, e.g.
    -- $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
    password_hash   TEXT    NOT NULL,

    -- What the user is allowed to do. The CHECK stops any other value
    -- being stored, even by a bug elsewhere in the code.
    role            TEXT    NOT NULL DEFAULT 'patient'
                            CHECK (role IN ('patient', 'doctor', 'admin')),

    -- Used to lock an account after repeated wrong passwords.
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,

    created_at      TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Two-factor authentication (TOTP). One row per user who has set it up.
-- A separate table, so accounts without 2FA simply have no row here.
CREATE TABLE IF NOT EXISTS two_factor (
    user_id           INTEGER PRIMARY KEY REFERENCES users(id),

    -- The shared TOTP secret, encrypted with AES-256-GCM (nonce +
    -- ciphertext). Unlike a password it can't be hashed, because the
    -- server needs the real value to compute codes. See auth/totp.py.
    encrypted_secret  BLOB    NOT NULL,

    -- 0 while setup is in progress (QR shown but no code confirmed yet),
    -- 1 once the user has proved their phone has the secret.
    enabled           INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),

    -- The 30-second time step of the last code accepted. A code from this
    -- step or earlier is refused, so each code works only once.
    last_used_step    INTEGER,

    created_at        TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS records (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id       INTEGER NOT NULL REFERENCES users(id),  --patient who gets the records
    author_id        INTEGER NOT NULL REFERENCES users(id),  --the author of the records, in this case, the doctor
    encrypted_body   BLOB    NOT NULL,   -- title and text get encrypted
    wrapped_key      BLOB    NOT NULL,   -- the body gets wrapped in a key, the key is the encrypted with patients public key
    created_at       TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS record_shares (
    record_id   INTEGER NOT NULL REFERENCES records(id),  --teh record that the patient shares with
    doctor_id   INTEGER NOT NULL REFERENCES users(id),   --the doctor that receives the records from the patient
    granted_at  TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP, -- when the patient allows accces to the doctor to the records
    PRIMARY KEY (record_id, doctor_id)
);

-- ===================== Integrity and audit =====================

-- Tamper-evident audit log. Each row's entry_hash is an HMAC-SHA256 over
-- its own fields plus the previous row's entry_hash, so the rows form a
-- chain: editing, deleting or inserting a row breaks the chain at that
-- point. The HMAC key lives in instance/, not in this database, so
-- someone with only database access can't recompute valid hashes to
-- cover their tracks. See audit/log.py.
CREATE TABLE IF NOT EXISTS audit_log (
    -- AUTOINCREMENT, not plain INTEGER PRIMARY KEY: SQLite would otherwise
    -- reuse the ID of a deleted last row. IDs are never reused here, so a
    -- gap in the numbering is itself a sign that a row was removed.
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp   TEXT    NOT NULL,   -- UTC, ISO 8601, set by log_event()

    -- Deliberately no REFERENCES users(id). foreign_keys is ON (db.py),
    -- so a foreign key would stop a user ever being deleted while they
    -- have log entries. The log must outlive what it describes.
    -- NULL when there's no known user, e.g. a failed login.
    user_id     INTEGER,

    action      TEXT    NOT NULL,   -- event type, e.g. 'login', 'record_viewed'

    -- IDs only, e.g. 'record_id=12'. Never medical content or passwords:
    -- the log is read by admins, who have no right to see patient data.
    details     TEXT    NOT NULL DEFAULT '',

    prev_hash   TEXT    NOT NULL,   -- previous row's entry_hash (64 zeros for the first row)
    entry_hash  TEXT    NOT NULL    -- HMAC-SHA256 of this row, hex
    
);

-- Each doctor's Ed25519 key pair, made the first time they sign.
-- The private key is encrypted with the doctor's password, so even with
-- the database, nobody else can sign as them.
CREATE TABLE IF NOT EXISTS signing_keys (
    doctor_id              INTEGER PRIMARY KEY REFERENCES users(id),
    public_key             BLOB NOT NULL,   -- raw 32 bytes, used to verify
    encrypted_private_key  BLOB NOT NULL,   -- PEM, password-encrypted
    created_at             TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One signature per record, kept separate so Filip's records table is untouched.
CREATE TABLE IF NOT EXISTS record_signatures (
    record_id   INTEGER PRIMARY KEY REFERENCES records(id),
    doctor_id   INTEGER NOT NULL REFERENCES users(id),
    signature   BLOB NOT NULL,              -- 64-byte Ed25519 signature
    signed_at   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);