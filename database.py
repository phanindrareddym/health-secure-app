import sqlite3
import pyotp
from datetime import datetime
from zoneinfo import ZoneInfo

DB_PATH = "auth.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ============================================================
#  INIT DATABASE (ALL TABLES)
# ============================================================
def init_db():
    conn = get_db()
    cur = conn.cursor()

    # -------------------------
    # USERS TABLE
    # -------------------------
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

    # -------------------------
    # TRUSTED DEVICES (NEW)
    # -------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS trusted_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_fingerprint TEXT NOT NULL,
        device_name TEXT,              -- user-friendly name (editable)
        auto_name TEXT,                -- system-generated name
        ip TEXT,
        location TEXT,
        created_at INTEGER,
        last_used INTEGER,
        expires_at INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Add missing columns dynamically
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

    cur.execute("PRAGMA table_info(users)")
    existing_cols = [row["name"] for row in cur.fetchall()]

    for col, col_type, default in new_columns:
        if col not in existing_cols:
            cur.execute(f"ALTER TABLE users ADD COLUMN {col} {col_type} DEFAULT {default}")

    # -------------------------
    # MFA TABLE
    # -------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS mfa (
        user_id INTEGER UNIQUE,
        secret TEXT,
        enabled INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # -------------------------
    # SECURITY EVENTS
    # -------------------------
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

    # -------------------------
    # LOGIN HISTORY
    # -------------------------
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

    # -------------------------
    # ⭐ USER SESSIONS TABLE (NEW)
    # -------------------------
    cur.execute("""
    CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_id TEXT NOT NULL,
        ip TEXT,
        location TEXT,
        user_agent TEXT,
        device_type TEXT,
        login_time INTEGER,
        last_activity INTEGER,
        is_active INTEGER DEFAULT 1
    )
    """)

    conn.commit()
    conn.close()


# ============================================================
#  USER MANAGEMENT
# ============================================================
def create_user(username, email, name, role="user", password_hash=None):
    conn = get_db()
    cur = conn.cursor()

    if password_hash is None:
        password_hash = "oauth"  # nosec

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
    row = cur.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY id")
    users = cur.fetchall()

    result = []
    for u in users:
        u = dict(u)
        u["history"] = get_login_history(u["id"])
        result.append(u)

    conn.close()
    return result


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


# ============================================================
#  MFA
# ============================================================
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


# ============================================================
#  LOGIN HISTORY
# ============================================================
def insert_login_history(user_id, time, ip, location, provider, device, os, browser):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO login_history (user_id, time, ip, location, provider, device, os, browser)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, time, ip, location, provider, device, os, browser))
    conn.commit()
    conn.close()


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
# ============================================================
#  SESSION MANAGEMENT (NEW)
# ============================================================
def record_user_session(user_id, session_id, ip, location, user_agent, device_type, login_time):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO user_sessions (
            user_id, session_id, ip, location, user_agent, device_type,
            login_time, last_activity, is_active
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
    """, (
        user_id, session_id, ip, location, user_agent, device_type,
        login_time, login_time
    ))
    conn.commit()
    conn.close()


def update_last_activity():
    try:
        from flask import session
        if "session_id" in session:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE user_sessions
                SET last_activity = ?
                WHERE session_id = ? AND is_active = 1
            """, (int(datetime.now().timestamp()), session["session_id"]))
            conn.commit()
            conn.close()
    except Exception as e:
        app.logger.error(f"Database close error: {e}")


# ============================================================
#  TRUSTED DEVICES (NEW)
# ============================================================

def record_trusted_device(user_id, fingerprint, auto_name, ip, location):
    """Insert a new trusted device with 30-day expiration."""
    conn = get_db()
    cur = conn.cursor()

    now = int(datetime.now().timestamp())
    expires = now + (30 * 24 * 60 * 60)  # 30 days

    cur.execute("""
        INSERT INTO trusted_devices (
            user_id, device_fingerprint, device_name, auto_name,
            ip, location, created_at, last_used, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        fingerprint,
        None,          # user-friendly name (editable later)
        auto_name,     # system-generated name
        ip,
        location,
        now,
        now,
        expires
    ))

    conn.commit()
    conn.close()


def is_trusted_device(user_id, fingerprint):
    """Return True if device is trusted and not expired."""
    conn = get_db()
    cur = conn.cursor()

    now = int(datetime.now().timestamp())

    cur.execute("""
        SELECT * FROM trusted_devices
        WHERE user_id = ?
        AND device_fingerprint = ?
        AND expires_at > ?
    """, (user_id, fingerprint, now))

    row = cur.fetchone()
    conn.close()

    return row is not None


def update_trusted_device_usage(user_id, fingerprint):
    """Update last_used timestamp when a trusted device logs in."""
    conn = get_db()
    cur = conn.cursor()

    now = int(datetime.now().timestamp())

    cur.execute("""
        UPDATE trusted_devices
        SET last_used = ?
        WHERE user_id = ? AND device_fingerprint = ?
    """, (now, user_id, fingerprint))

    conn.commit()
    conn.close()


def get_trusted_devices(user_id):
    """Return all trusted devices for a user."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT * FROM trusted_devices
        WHERE user_id = ?
        ORDER BY last_used DESC
    """, (user_id,))

    rows = cur.fetchall()
    conn.close()
    return rows


def update_trusted_device_name(device_id, new_name):
    """Rename a trusted device."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        UPDATE trusted_devices
        SET device_name = ?
        WHERE id = ?
    """, (new_name, device_id))

    conn.commit()
    conn.close()


def remove_trusted_device(device_id):
    """Delete a single trusted device."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM trusted_devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()


def remove_all_trusted_devices(user_id):
    """Delete all trusted devices for a user."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute("DELETE FROM trusted_devices WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
