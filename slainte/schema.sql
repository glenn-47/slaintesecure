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
