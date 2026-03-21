import sqlite3

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

    # MFA table (for later)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS mfa (
        user_id INTEGER UNIQUE,
        secret TEXT,
        enabled INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    # Security events table (for suspicious session logs, etc.)
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

    # Azure users won't have a password, so set a placeholder
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


def update_user(user_id, email, name, role):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE users
        SET email = ?, name = ?, role = ?
        WHERE id = ?
    """, (email, name, role, user_id))
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