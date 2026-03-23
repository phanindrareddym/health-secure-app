import sqlite3
import pyotp

DB_PATH = "auth.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()

    # Users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        email TEXT,
        name TEXT,
        role TEXT DEFAULT 'user'
    )
    """)

    # MFA table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS mfa (
        user_id INTEGER UNIQUE,
        secret TEXT,
        enabled INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Security events table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT,
        ip TEXT,
        device TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def create_user(username, email, name, role="user", password_hash=None):
    conn = get_db()
    cur = conn.cursor()

    # Azure users won't have a password
    if password_hash is None:
        password_hash = "azure-oauth"

    cur.execute("""
        INSERT INTO users (username, password_hash, email, name, role)
        VALUES (?, ?, ?, ?, ?)
    """, (username, password_hash, email, name, role))

    conn.commit()
    conn.close()

def get_user_by_username(username):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()
    return user


def get_all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id")
    users = cur.fetchall()
    conn.close()
    return users


def get_user_by_id(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    conn.close()
    return user


def get_mfa_record(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM mfa WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def set_mfa_secret(user_id, secret):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO mfa (user_id, secret, enabled)
        VALUES (?, ?, 0)
        ON CONFLICT(user_id) DO UPDATE SET secret = excluded.secret
    """, (user_id, secret))
    conn.commit()
    conn.close()


def enable_mfa(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE mfa SET enabled = 1 WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def is_mfa_enabled(user_id):
    record = get_mfa_record(user_id)
    return record and record["enabled"] == 1


def verify_mfa_code(user_id, code):
    record = get_mfa_record(user_id)
    if not record or not record["secret"]:
        return False

    totp = pyotp.TOTP(record["secret"])
    return totp.verify(code)

def update_user(user_id, name, email, role):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET name = ?, email = ?, role = ?
        WHERE id = ?
    """, (name, email, role, user_id))
    conn.commit()
    conn.close()


def update_user_password(user_id, new_password_hash):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET password_hash = ?
        WHERE id = ?
    """, (new_password_hash, user_id))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()