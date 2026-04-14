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

    new_columns = [
        ("status", "TEXT", "'active'"),
        ("mfa_enabled", "INTEGER", "0"),
        ("last_login", "TEXT", "NULL"),
        ("last_ip", "TEXT", "NULL"),
        ("last_location", "TEXT", "NULL"),
        ("last_provider", "TEXT", "NULL"),
        ("last_device", "TEXT", "NULL"),
        ("last_os", "TEXT", "NULL"),
        ("last_browser", "TEXT", "NULL"),
    ]

    # Check existing columns
    cur.execute("PRAGMA table_info(users)")
    existing_cols = [row["name"] for row in cur.fetchall()]

    # Add missing columns
    for col, col_type, default in new_columns:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type} DEFAULT {default}")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS mfa (
        user_id INTEGER UNIQUE,
        secret TEXT,
        enabled INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

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

    cur.execute("""
    CREATE TABLE IF NOT EXISTS login_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        time TEXT,
        ip TEXT,
        location TEXT,
        provider TEXT,
        device TEXT,
        os TEXT,
        browser TEXT
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

    # Attach login history to each user
    result = []
    for u in users:
        u = dict(u)
        u["history"] = get_login_history(u["id"])
        result.append(u)

    conn.close()
    return result

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

def update_user(user_id, name, email, role, status, mfa_enabled):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET name = ?, email = ?, role = ?, status = ?, mfa_enabled = ?
        WHERE id = ?
    """, (name, email, role, status, mfa_enabled, user_id))
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

def update_user_last_login(user_id, last_login, last_ip, last_location,
                           last_provider, last_device, last_os, last_browser):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users SET
            last_login = ?,
            last_ip = ?,
            last_location = ?,
            last_provider = ?,
            last_device = ?,
            last_os = ?,
            last_browser = ?
        WHERE id = ?
    """, (last_login, last_ip, last_location, last_provider,
          last_device, last_os, last_browser, user_id))
    conn.commit()
    conn.close()

def insert_login_history(user_id, time, ip, location, provider, device, os, browser):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO login_history (user_id, time, ip, location, provider, device, os, browser)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, time, ip, location, provider, device, os, browser))
    conn.commit()
    conn.close()

from datetime import datetime
from zoneinfo import ZoneInfo

def record_user_login(user, ip, provider, location, device_info):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO login_history (user_id, time, ip, location, provider, device, os, browser)
        VALUES (?, datetime('now'), ?, ?, ?, ?, ?, ?)
    """, (
        user["id"],
        ip,
        location,
        provider,
        device_info.get("device"),
        device_info.get("os"),
        device_info.get("browser")
    ))

    cur.execute("""
        UPDATE users SET
            last_login = datetime('now'),
            last_ip = ?,
            last_location = ?,
            last_provider = ?,
            last_device = ?,
            last_os = ?,
            last_browser = ?
        WHERE id = ?
    """, (
        ip,
        location,
        provider,
        device_info.get("device"),
        device_info.get("os"),
        device_info.get("browser"),
        user["id"]
    ))

    conn.commit()
    conn.close()

def get_login_history(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT * FROM login_history
        WHERE user_id = ?
        ORDER BY time DESC
        LIMIT 20
    """, (user_id,))
    rows = cur.fetchall()
    conn.close()
    return rows

