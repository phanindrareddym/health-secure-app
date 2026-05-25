from functools import wraps
from collections import defaultdict
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import time
import uuid
import os
import base64
import requests
import jwt
from jwt import PyJWKClient
from aws_security import send_security_event
from urllib.request import urlopen
from zoneinfo import ZoneInfo
import json
from flask import request, jsonify
import hashlib
import pyotp
import qrcode
import csv
import io
from urllib.parse import urlencode
from flask import (
    Response,
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    make_response,
)
from user_agents import parse as parse_ua
from database import (
    record_user_session,
    get_db,
    init_db,
    get_user_by_username,
    record_user_login,
    get_all_users,
    get_user_by_id,
    update_user,
    update_user_password,
    create_user,  is_mfa_enabled,
    verify_mfa_code,
    enable_mfa,
    set_mfa_secret,
    get_mfa_record,
    delete_user,
)
from dotenv import load_dotenv
from io import BytesIO
load_dotenv()
GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY")

import re

USERNAME_REGEX = r"^[A-Za-z][A-Za-z0-9_]{2,19}$"
PASSWORD_REGEX = (
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)"
    r"(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
)

def reset_session():
    """
    Clear ONLY user-related session keys.
    Keep admin_* keys so admin and user sessions can coexist.
    """
    for key in list(session.keys()):
        if key.startswith("admin_"):
            continue
        session.pop(key, None)
# -----------------------------
# Decorators
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        if request.path.startswith("/api/"):
            return f(*args, **kwargs)

        if request.path.startswith("/admin/login"):
            return f(*args, **kwargs)

        if request.path.startswith("/admin"):
            return f(*args, **kwargs)

        if request.path in ["/login", "/register", "/mfa/setup", "/mfa/verify"]:
            return f(*args, **kwargs)

        if request.path.startswith("/static"):
            return f(*args, **kwargs)

        if not session.get("authenticated"):
            return redirect("/login")

        if session.get("skip_suspicious_check"):
            session["last_activity"] = time.time()
            return f(*args, **kwargs)

        reason = detect_suspicious_session()
        if reason:
            session["suspicious_logout"] = True
            return redirect("/login")

        session["last_activity"] = time.time()
        return f(*args, **kwargs)

    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):

        # Allow admin login page
        if request.path == "/admin/login":
            return f(*args, **kwargs)

        # Allow static files
        if request.path.startswith("/static"):
            return f(*args, **kwargs)

        # Must be authenticated admin
        if not session.get("admin_is_admin"):
            return redirect("/admin/login")

        if not session.get("admin_username"):
            return redirect("/admin/login")

        if not session.get("admin_jwt"):
            return redirect("/admin/login")

        # Device fingerprint check
        current_fp = get_device_fingerprint()
        if session.get("admin_device_fingerprint") != current_fp:
            return redirect("/admin/login")

        # Timeout check
        now = time.time()
        last = session.get("admin_last_activity", now)
        if now - last > 1800:
            return redirect("/admin/login")

        session["admin_last_activity"] = now
        return f(*args, **kwargs)

    return wrapper

def reverse_geocode(lat, lon):
    if not lat or not lon:
        return None

    try:
        url = (
            "https://maps.googleapis.com/maps/api/geocode/json"
            f"?latlng={lat},{lon}&key={GOOGLE_MAPS_API_KEY}"
        )

        resp = requests.get(url, timeout=5)
        data = resp.json()

        results = data.get("results", [])
        if results:
            return results[0].get("formatted_address")

        return f"GPS ({lat}, {lon})"
    except Exception:
        app.logger.error(f"Reverse geocode failed: {e}")
        return f"GPS ({lat}, {lon})"
    
def generate_qr_code(data):
    qr = qrcode.make(data)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("utf-8")

def detect_suspicious_login(username, ip, location, device):
    alerts = []

    prev = last_login.get(username)
    if not prev or not isinstance(prev, dict):
        return alerts

    prev_device_raw = prev.get("device")

    if isinstance(prev_device_raw, dict):
        prev_browser = prev_device_raw.get("browser")
        prev_device_name = prev_device_raw.get("device")
    else:
        prev_browser = prev.get("browser")
        prev_device_name = prev_device_raw

    prev_location = prev.get("location")
    curr_browser = device.get("browser")
    curr_device_name = device.get("device")
    curr_location = location.get("location")

    if prev_location and curr_location and prev_location != curr_location:
        alerts.append(
            f"New location detected: {curr_location} (previous: {prev_location})"
        )

    if prev_device_name and curr_device_name and prev_device_name != curr_device_name:
        alerts.append(
            f"New device detected: {curr_device_name} (previous: {prev_device_name})"
        )

    if prev_browser and curr_browser and prev_browser != curr_browser:
        alerts.append(
            f"New browser detected: {curr_browser} (previous: {prev_browser})"
        )

    return alerts

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
        if "session_id" in session:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("""
                UPDATE user_sessions
                SET last_activity = ?
                WHERE session_id = ? AND is_active = 1
            """, (int(time.time()), session["session_id"]))
            conn.commit()
            conn.close()
    except Exception as e:
        app.logger.error(f"Database close error: {e}")


def get_device_info():
    ua_string = request.headers.get("User-Agent", "")

    if not ua_string or ua_string.strip() == "":
        return {
            "browser": "Unknown browser",
            "os": "Unknown OS",
            "device": "Unknown device",
            "device_type": "Unknown"
        }

    ua = parse_ua(ua_string)

    # OS
    if "Windows NT 10.0" in ua_string:
        if "Windows 11" in ua_string or "Edg/" in ua_string:
            os_label = "Windows 11"
        else:
            os_label = "Windows 10"
    else:
        os_label = f"{ua.os.family} {ua.os.version_string}".strip() or "Unknown OS"

    # Browser
    family = ua.browser.family.lower()
    version = ua.browser.version_string or ""

    if "edg" in family:
        browser = f"Edge {version}"
    elif "chrome" in family:
        browser = f"Chrome {version}"
    elif "firefox" in family:
        browser = f"Firefox {version}"
    elif "safari" in family:
        browser = f"Safari {version}"
    else:
        browser = ua.browser.family or "Unknown Browser"

    # Device type
    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "PC"
    else:
        device_type = "Other"

    return {
        "browser": browser,
        "os": os_label,
        "device": device_type,
        "device_type": device_type,
    }

def get_client_ip():
    # Prefer X-Forwarded-For (Render, Cloudflare, Nginx, etc.)
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        # XFF format: "client, proxy1, proxy2"
        ip = xff.split(",")[0].strip()
    else:
        ip = request.remote_addr or "0.0.0.0"

    # Normalize localhost patterns
    if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("127."):
        return "localhost"

    return ip

def get_ip_location(ip):
    try:
        if ip in ("127.0.0.1", "localhost"):
            return {
                "location": "Localhost",
                "lat": 40.3573,
                "lon": -74.6672,
                "isp": "Local Development",
                "asn": "N/A",
            }

        url = f"https://ipapi.co/{ip}/json/"
        resp = requests.get(url, timeout=2)

        if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
            data = resp.json()
        else:
            raise ValueError("Non-JSON response")

        return {
            "location": f"{data.get('city')}, {data.get('region')}, {data.get('country_name')}",
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "isp": data.get("org"),
            "asn": data.get("asn"),
        }

    except Exception as e:
        app.logger.error(f"IP geolocation failed: {e}")
        return {
            "location": "Unknown",
            "lat": None,
            "lon": None,
            "isp": "Unknown",
            "asn": "Unknown",
        }

def get_gps_location():
    """
    Prefer browser GPS stored in session (from /update_gps).
    Fallback to IP-based geolocation if GPS is not available.
    """
    lat = session.get("gps_lat")
    lon = session.get("gps_lon")
    address = session.get("gps_address")

    # ⭐ If browser GPS exists → use it
    if lat and lon:
        return {
            "lat": lat,
            "lon": lon,
            "location": address or f"GPS ({lat}, {lon})",
            "address": address
        }

    # ⭐ Otherwise fallback to IP-based location
    ip = get_client_ip()
    ip_loc = get_ip_location(ip)

    return {
        "lat": ip_loc.get("lat"),
        "lon": ip_loc.get("lon"),
        "location": ip_loc.get("location") or "Unknown",
        "address": ip_loc.get("address")
    }


def get_device_fingerprint():
    ua_string = request.headers.get("User-Agent", "")
    ua = parse_ua(ua_string)

    os_family = ua.os.family
    os_version = ua.os.version_string

    if os_family == "Windows" and os_version.startswith("10"):
        os_label = "Windows 10/11"
    else:
        os_label = f"{os_family} {os_version}".strip()

    browser = f"{ua.browser.family} {ua.browser.version_string}".strip()

    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "Desktop"
    else:
        device_type = "Other"

    # Build raw fingerprint dict
    raw_fp = {
        "browser": browser,
        "os": os_label,
        "device": ua.device.family or "Other",
        "device_type": device_type,
    }

    # Convert dict → stable JSON string
    fp_json = json.dumps(raw_fp, sort_keys=True)

    # Hash JSON → final fingerprint string
    fp_hash = hashlib.sha256(fp_json.encode()).hexdigest()

    return fp_hash

def detect_suspicious_session():
    """Return a reason string if session is suspicious, else None."""
    if "username" not in session:
        return None

    now = time.time()
    current_fp = get_device_fingerprint()          # string hash
    stored_fp = session.get("device_fingerprint")  # string hash
    last_activity = session.get("last_activity", 0)
    login_time = session.get("login_time", 0)

    # A. Device fingerprint changed
    if stored_fp and stored_fp != current_fp:
        return "Device fingerprint changed"

    # C. Idle timeout (15 minutes)
    if now - last_activity > IDLE_TIMEOUT:
        return f"Idle timeout exceeded: {int(now - last_activity)} seconds"

    # D. Absolute session lifetime (12 hours)
    if now - login_time > SESSION_LIFETIME:
        return f"Session lifetime exceeded: {int(now - login_time)} seconds"

    return None

def forward_to_splunk(event):
    if not ENABLE_SPLUNK_FORWARDING:
        return

    try:
        payload = {"event": event}

        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"
        }

        response = requests.post(
            SPLUNK_HEC_URL,
            data=json.dumps(payload),
            headers=headers,
            verify=False
        )

        if response.status_code != 200:
            print("SPLUNK ERROR:", response.text)

    except Exception as e:
        print("SPLUNK FORWARDING FAILED:", str(e))

def complete_login_from_pending():
    user_id = session.get("pending_user_id")
    username = session.get("pending_username")
    role = session.get("pending_role")

    if not user_id or not username or not role:
        return redirect("/login")

    role = role.lower()

    # Clear pending
    session.pop("pending_user_id", None)
    session.pop("pending_username", None)
    session.pop("pending_role", None)
    session.pop("mfa_setup_secret", None)

    now = time.time()
    device_fp = get_device_fingerprint()
    ip = get_client_ip()
    gps = get_gps_location()

    lat = gps.get("lat")
    lon = gps.get("lon")
    place = reverse_geocode(lat, lon)
    session["gps_address"] = place

    # ⭐ ALWAYS use backend UA parser (stable)
    device = get_device_info()

    # Core session
    session["authenticated"] = True
    session["logged_in"] = True
    session["skip_suspicious_check"] = True

    session["user_id"] = user_id
    session["user_username"] = username
    session["user_is_admin"] = (role == "admin")
    session["user_login_time"] = now
    session["user_last_activity"] = now
    session["user_device_fingerprint"] = device_fp

    session["username"] = username
    session["login_time"] = now
    session["last_activity"] = now
    session["device_fingerprint"] = device_fp
    session["user_role"] = role

    if "login_provider" not in session:
        session["login_provider"] = "Normal"

    if role == "admin":
        session["admin_is_admin"] = True

    # Trusted device check
    from database import is_trusted_device, update_trusted_device_usage

    if is_trusted_device(user_id, device_fp):
        session["trusted_device"] = True
        session["skip_mfa"] = True
        session["risk_level"] = "low"
        session["skip_suspicious_check"] = True
        update_trusted_device_usage(user_id, device_fp)
    else:
        session["trusted_device"] = False
        session["skip_mfa"] = False
        session["risk_level"] = "normal"

    # Suspicious login detection (safe)
    alerts = detect_suspicious_login(
        username,
        ip,
        {"location": place},
        device
    )
    session["user_login_alerts"] = alerts

    provider = session["login_provider"]

    log_event("login", "green", ip, f"{provider} login by {username} from {place}")

    user = get_user_by_id(user_id)

    # ⭐ Unified event record (flat, consistent)
    event_record = {
        "username": username,
        "provider": provider,
        "ip": ip,
        "location": place,
        "lat": lat,
        "lon": lon,
        "device": device.get("device"),
        "os": device.get("os"),
        "browser": device.get("browser"),
        "time": datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
    }

    login_history[username].append(event_record)
    last_login[username] = event_record

    record_user_login(
        user=user,
        ip=ip,
        provider=provider,
        location=place,
        device_info=device,
    )

    return redirect("/")
# -----------------------------
# App + session config
# -----------------------------
from werkzeug.middleware.proxy_fix import ProxyFix
from collections import defaultdict

app = Flask(__name__)
app.config["SESSION_COOKIE_NAME"] = "app_session"
app.config["SESSION_COOKIE_DOMAIN"] = None

IS_PROD = bool(os.environ.get("RENDER"))

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-change-this-to-a-strong-secret")
app.config["SESSION_COOKIE_HTTPONLY"] = True

if IS_PROD:
    # Render / HTTPS
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["PREFERRED_URL_SCHEME"] = "https"
else:
    # Local development (HTTP)
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["PREFERRED_URL_SCHEME"] = "http"

SESSION_LIFETIME = 60 * 60 * 12
IDLE_TIMEOUT = 60 * 15

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-super-strong-secret-key")
JWT_ALGO = "HS256"
JWT_EXPIRATION = 3600

AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "eda8e9bc-72cf-449c-a4e6-725e6c6bd0d8")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "d0b15a55-7aa3-468b-a112-757f0f762375")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")

AZURE_REDIRECT_URI = os.environ.get(
    "AZURE_REDIRECT_URI",
    "http://localhost:5000/auth/azure/callback",
)

AZURE_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
AZURE_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
AZURE_JWKS_URL = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
AZURE_ISSUER = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN", "healthsecure-app.us.auth0.com")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")

AUTH0_REDIRECT_URI = os.environ.get(
    "AUTH0_REDIRECT_URI",
    "http://localhost:5000/auth/callback"
)

AUTH0_AUTH_URL = f"https://{AUTH0_DOMAIN}/authorize"
AUTH0_TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"
AUTH0_USERINFO_URL = f"https://{AUTH0_DOMAIN}/userinfo"
AUTH0_JWKS_URL = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"

API_AUDIENCE = "https://health-secure-api"
ALGORITHMS = ["RS256"]

SPLUNK_HEC_URL = "https://localhost:8088/services/collector"
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
ENABLE_SPLUNK_FORWARDING = True  # keep this OFF for now

init_db()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "Phani") # nosec
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")


request_log = defaultdict(list)
security_events = []

OAUTH_CLIENTS = {
    "demo-client": {
        "client_id": "demo-client",
        "client_secret": os.getenv("DEMO_OAUTH_SECRET", "demo-secret"),  # nosec
        "redirect_uris": [
            "http://localhost:5001/callback",
        ],
        "allowed_scopes": ["openid", "profile", "email"],
    }
}

AUTH_CODES = {}
REFRESH_TOKENS = {}

OAUTH_CODE_LIFETIME = 300
ACCESS_TOKEN_LIFETIME = 900
REFRESH_TOKEN_LIFETIME = 86400

login_history = defaultdict(list)
last_login = {}
users = {}

@app.route("/debug-cookie")
def debug_cookie():
    session["test"] = "hello"
    print("SESSION AFTER SET:", dict(session))
    return "Cookie set"

PUBLIC_ROUTES = {
    "/update_gps",
    "/auth/azure/login",
    "/auth/azure/callback",
    "/auth/login",
    "/auth/callback",
    "/login",
    "/register",
    "/logout",
    "/static",
    "/favicon.ico",
}

@app.before_request
def enforce_session_timeout():
    path = request.path

    for p in PUBLIC_ROUTES:
        if path.startswith(p):
            return

    if path.startswith("/api/"):
        return

    if path.startswith("/oauth/"):
        return

    if path.startswith("/admin"):
        if path == "/admin/login":
            return

        if not session.get("admin_is_admin"):
            for k in list(session.keys()):
                if k.startswith("admin_"):
                    session.pop(k, None)
            return redirect("/admin/login")

        current_fp = get_device_fingerprint()
        if session.get("admin_device_fingerprint") and session["admin_device_fingerprint"] != current_fp:
            for k in list(session.keys()):
                if k.startswith("admin_"):
                    session.pop(k, None)
            return redirect("/admin/login")

        now = time.time()
        if now - session.get("admin_login_time", 0) > SESSION_LIFETIME:
            for k in list(session.keys()):
                if k.startswith("admin_"):
                    session.pop(k, None)
            return redirect("/admin/login")

        if now - session.get("admin_last_activity", 0) > IDLE_TIMEOUT:
            for k in list(session.keys()):
                if k.startswith("admin_"):
                    session.pop(k, None)
            return redirect("/admin/login")

        session["admin_last_activity"] = now
        return

    if path.startswith("/mfa/"):
        return

    if not session.get("user_username"):
        return redirect("/login")

    current_fp = get_device_fingerprint()
    if session.get("user_device_fingerprint") and session["user_device_fingerprint"] != current_fp:
        reset_session()
        return redirect("/login")

    now = time.time()
    if now - session.get("user_login_time", 0) > SESSION_LIFETIME:
        reset_session()
        return redirect("/login")

    if now - session.get("user_last_activity", 0) > IDLE_TIMEOUT:
        reset_session()
        return redirect("/login")

    session["user_last_activity"] = now


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        email = request.form.get("email", "").strip()
        name = request.form.get("name", "").strip()

        # Required fields
        if not username or not password:
            return render_template("register.html", error="Username and password are required")

        # Username validation
        if not re.match(USERNAME_REGEX, username):
            return render_template(
                "register.html",
                error="Username must be 3–20 characters, start with a letter, and contain only letters, numbers, or underscores."
            )

        # Password validation
        if not re.match(PASSWORD_REGEX, password):
            return render_template(
                "register.html",
                error="Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
            )

        # Check if user already exists in SQLite
        existing = get_user_by_username(username)
        if existing:
            return render_template("register.html", error="Username already exists")

        # Hash password for new users
        password_hash = generate_password_hash(password)

        # Create user in SQLite
        create_user(
            username=username,
            email=email or f"{username}@example.com",
            name=name or username,
            password_hash=password_hash,
            role="user",
        )

        return render_template("register.html", success="Account created! You can now login.")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        session.pop("raw_device_info", None)

        user = get_user_by_username(username)
        if not user:
            from aws_security import send_security_event
            send_security_event(
                event_type="login_failed",
                user_id=None,
                username=username,
                ip=request.remote_addr,
                location="Unknown",
                device="Unknown",
                provider="password",
                risk_score=5
            )
            return render_template("login.html", error="Invalid username or password")

        status = user["status"] if "status" in user.keys() else "active"
        if status in ("locked", "suspended"):
            return render_template("account_blocked.html", reason=status)

        stored = user["password_hash"]
        password_ok = False

        if isinstance(stored, str) and stored.startswith(("pbkdf2:", "scrypt:", "argon2:", "sha256$")):
            try:
                password_ok = check_password_hash(stored, password)
            except:
                password_ok = False
        else:
            password_ok = (stored == password)

        if not password_ok:
            from aws_security import send_security_event
            send_security_event(
                event_type="login_failed",
                user_id=user["id"],
                username=user["username"],
                ip=request.remote_addr,
                location="Unknown",
                device="Unknown",
                provider="password",
                risk_score=5
            )
            return render_template("login.html", error="Invalid username or password")

        role = user["role"].lower()

        session_id = str(uuid.uuid4())
        session["session_id"] = session_id

        ip = request.remote_addr
        user_agent = request.headers.get("User-Agent", "")
        device = get_device_info()
        device_type = device.get("device_type", "Unknown")
        location = session.get("gps_address", "Unknown")
        login_time = int(time.time())

        record_user_session(
            user_id=user["id"],
            session_id=session_id,
            ip=ip,
            location=location,
            user_agent=user_agent,
            device_type=device_type,
            login_time=login_time,
        )

        from aws_security import send_security_event
        send_security_event(
            event_type="session_start",
            user_id=user["id"],
            username=user["username"],
            ip=ip,
            location=location,
            device=device_type,
            provider="password",
            risk_score=0
        )

        session["pending_user_id"] = user["id"]
        session["pending_username"] = user["username"]
        session["pending_role"] = role
        session["login_provider"] = "Normal"

        send_security_event(
            event_type="login_success",
            user_id=user["id"],
            username=user["username"],
            ip=ip,
            location=location,
            device=device_type,
            provider="password",
            risk_score=0
        )

        if role == "admin":
            return complete_login_from_pending()

        if is_mfa_enabled(user["id"]):
            return redirect("/mfa/verify")

        return redirect("/mfa/setup")

    return render_template("login.html")


@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    if session.get("login_provider") != "Normal":
        return redirect("/login")

    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect("/login")

    user = get_user_by_id(user_id)
    if not user:
        return redirect("/login")

    if is_mfa_enabled(user_id):
        return redirect("/mfa/verify")

    from aws_security import send_security_event
    send_security_event(
        event_type="mfa_challenge",
        user_id=user_id,
        username=user["username"],
        ip=request.remote_addr,
        location=session.get("gps_address", "Unknown"),
        device="Unknown",
        provider="password",
        risk_score=0
    )

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("mfa_setup_secret")

        if not secret:
            return redirect("/login")

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            enable_mfa(user_id)

            send_security_event(
                event_type="mfa_success",
                user_id=user_id,
                username=user["username"],
                ip=request.remote_addr,
                location=session.get("gps_address", "Unknown"),
                device="Unknown",
                provider="password",
                risk_score=0
            )

            return complete_login_from_pending()
        else:
            send_security_event(
                event_type="mfa_failed",
                user_id=user_id,
                username=user["username"],
                ip=request.remote_addr,
                location=session.get("gps_address", "Unknown"),
                device="Unknown",
                provider="password",
                risk_score=10
            )

            issuer = "HealthSecure.us"
            username = user["username"]
            otpauth_url = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&digits=6&period=30"
            qr_image = generate_qr_code(otpauth_url)

            return render_template(
                "mfa_setup.html",
                error="Invalid code",
                secret=secret,
                qr_image=qr_image
            )

    secret = pyotp.random_base32()
    session["mfa_setup_secret"] = secret
    set_mfa_secret(user_id, secret)

    issuer = "HealthSecure.us"
    username = user["username"]
    otpauth_url = f"otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&digits=6&period=30"
    qr_image = generate_qr_code(otpauth_url)

    return render_template("mfa_setup.html", secret=secret, qr_image=qr_image)


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    if session.get("login_provider") != "Normal":
        return redirect("/login")

    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect("/login")

    user = get_user_by_id(user_id)
    if not user:
        return redirect("/login")

    if not is_mfa_enabled(user_id):
        return redirect("/mfa/setup")

    from aws_security import send_security_event
    send_security_event(
        event_type="mfa_challenge",
        user_id=user_id,
        username=user["username"],
        ip=request.remote_addr,
        location=session.get("gps_address", "Unknown"),
        device="Unknown",
        provider="password",
        risk_score=0
    )

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if verify_mfa_code(user_id, code):
            send_security_event(
                event_type="mfa_success",
                user_id=user_id,
                username=user["username"],
                ip=request.remote_addr,
                location=session.get("gps_address", "Unknown"),
                device="Unknown",
                provider="password",
                risk_score=0
            )
            return complete_login_from_pending()
        else:
            send_security_event(
                event_type="mfa_failed",
                user_id=user_id,
                username=user["username"],
                ip=request.remote_addr,
                location=session.get("gps_address", "Unknown"),
                device="Unknown",
                provider="password",
                risk_score=10
            )
            return render_template("mfa_verify.html", error="Invalid code")

    return render_template("mfa_verify.html")
# -----------------------------
# Auth0 Login (Authorization Code + PKCE)
# -----------------------------
@app.route("/auth/login")
def auth0_login():
    code_verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode("utf-8")
    session["auth0_code_verifier"] = code_verifier

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")

    params = {
        "response_type": "code",
        "client_id": AUTH0_CLIENT_ID,
        "redirect_uri": AUTH0_REDIRECT_URI,
        "scope": "openid profile email read:data",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "audience": "https://health-secure-api"
    }

    auth_url = f"{AUTH0_AUTH_URL}?{urlencode(params)}"
    return redirect(auth_url)


@app.route("/auth/callback")
def auth0_callback():
    code = request.args.get("code")
    if not code:
        return "Missing authorization code", 400

    code_verifier = session.get("auth0_code_verifier")
    if not code_verifier:
        return "Missing PKCE code verifier", 400

    token_payload = {
        "grant_type": "authorization_code",
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "code": code,
        "redirect_uri": AUTH0_REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    token_resp = requests.post(AUTH0_TOKEN_URL, data=token_payload, timeout=5)
    tokens = token_resp.json()
    if "id_token" not in tokens:
        return f"Token exchange failed: {tokens}", 400

    id_token = tokens["id_token"]
    access_token = tokens.get("access_token")
    session["user_api_access_token"] = access_token

    jwks_client = PyJWKClient(AUTH0_JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AUTH0_CLIENT_ID,
        options={"verify_iss": True},
        issuer=f"https://{AUTH0_DOMAIN}/"
    )

    email = claims.get("email")
    given = claims.get("given_name")
    family = claims.get("family_name")
    name = f"{given} {family}" if given and family else claims.get("name") or email

    existing = get_user_by_username(email)
    if not existing:
        create_user(username=email, email=email, name=name, password_hash="", role="user")
        existing = get_user_by_username(email)

    status = existing["status"] if "status" in existing.keys() else "active"
    if status in ("locked", "suspended"):
        return render_template("account_blocked.html", reason=status)

    session_id = str(uuid.uuid4())
    session["session_id"] = session_id

    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    device = get_device_info()
    device_type = device.get("device_type", "Unknown")
    location = session.get("gps_address", "Unknown")
    login_time = int(time.time())

    record_user_session(
        user_id=existing["id"],
        session_id=session_id,
        ip=ip,
        location=location,
        user_agent=user_agent,
        device_type=device_type,
        login_time=login_time,
    )

    from aws_security import send_security_event
    send_security_event(
        event_type="session_start",
        user_id=existing["id"],
        username=existing["username"],
        ip=ip,
        location=location,
        device=device_type,
        provider="Auth0",
        risk_score=0
    )

    send_security_event(
        event_type="login_success",
        user_id=existing["id"],
        username=existing["username"],
        ip=ip,
        location=location,
        device=device_type,
        provider="Auth0",
        risk_score=0
    )

    session["pending_user_id"] = existing["id"]
    session["pending_username"] = existing["username"]
    session["pending_role"] = existing["role"]
    session["login_provider"] = "Auth0"
    session["device_fingerprint"] = get_device_fingerprint()

    return complete_login_from_pending()

@app.route("/auth/azure/login")
def azure_login():
    verifier = base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode("utf-8")
    session["azure_pkce_verifier"] = verifier

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).rstrip(b"=").decode("utf-8")

    params = {
        "client_id": AZURE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": AZURE_REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    auth_url = AZURE_AUTH_URL + "?" + urlencode(params)
    return redirect(auth_url)


@app.route("/auth/azure/callback")
def azure_callback():
    code_verifier = session.get("azure_pkce_verifier")
    if not code_verifier:
        return "Missing PKCE verifier in session", 400

    code = request.args.get("code")
    if not code:
        return "Missing authorization code", 400

    token_data = {
        "client_id": AZURE_CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": AZURE_REDIRECT_URI,
        "code_verifier": code_verifier,
        "client_secret": AZURE_CLIENT_SECRET,
    }

    token_resp = requests.post(AZURE_TOKEN_URL, data=token_data, timeout=5)
    tokens = token_resp.json()
    id_token = tokens.get("id_token")
    if not id_token:
        return f"No ID token returned: {tokens}", 400

    jwks_client = PyJWKClient(AZURE_JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)

    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=AZURE_CLIENT_ID,
        options={"verify_iss": False},
    )

    email = claims.get("preferred_username") or claims.get("email")
    given = claims.get("given_name")
    family = claims.get("family_name")
    name = f"{given} {family}" if given and family else claims.get("name") or email

    existing = get_user_by_username(email)
    if not existing:
        create_user(username=email, email=email, name=name, password_hash="", role="user")
        existing = get_user_by_username(email)

    status = existing["status"] if "status" in existing.keys() else "active"
    if status in ("locked", "suspended"):
        return render_template("account_blocked.html", reason=status)

    session_id = str(uuid.uuid4())
    session["session_id"] = session_id

    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    device = get_device_info()
    device_type = device.get("device_type", "Unknown")
    location = session.get("gps_address", "Unknown")
    login_time = int(time.time())

    record_user_session(
        user_id=existing["id"],
        session_id=session_id,
        ip=ip,
        location=location,
        user_agent=user_agent,
        device_type=device_type,
        login_time=login_time,
    )

    from aws_security import send_security_event
    send_security_event(
        event_type="session_start",
        user_id=existing["id"],
        username=existing["username"],
        ip=ip,
        location=location,
        device=device_type,
        provider="Azure",
        risk_score=0
    )

    send_security_event(
        event_type="login_success",
        user_id=existing["id"],
        username=existing["username"],
        ip=ip,
        location=location,
        device=device_type,
        provider="Azure",
        risk_score=0
    )

    session["pending_user_id"] = existing["id"]
    session["pending_username"] = existing["username"]
    session["pending_role"] = existing["role"]
    session["login_provider"] = "Azure"
    session["device_fingerprint"] = get_device_fingerprint()

    return complete_login_from_pending()

@app.route("/logout")
def logout():
    from aws_security import send_security_event
    user_id = session.get("pending_user_id")
    username = session.get("pending_username")

    send_security_event(
        event_type="session_end",
        user_id=user_id,
        username=username,
        ip=request.remote_addr,
        location=session.get("gps_address", "Unknown"),
        device="Unknown",
        provider=session.get("login_provider", "Unknown"),
        risk_score=0
    )

    for key in list(session.keys()):
        if key.startswith("admin_"):
            continue
        session.pop(key, None)

    return redirect("/login")


@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")

    user = get_user_by_username(username)

    name = user["name"]
    email = user["email"]
    role = user["role"]
    is_admin = (role == "admin")

    # Device info (browser, os, device_type)
    device = get_device_info()
    device_type = device.get("device_type", "Unknown")

    # Trusted device status
    trusted_device = session.get("trusted_device", False)

    # Raw timestamps
    login_time = session.get("login_time")
    last_activity = session.get("last_activity")

    tz = ZoneInfo("America/New_York")

    login_time_str = None
    if login_time:
        login_time_str = datetime.fromtimestamp(login_time, tz).strftime("%Y-%m-%d %H:%M:%S")

    last_activity_str = None
    if last_activity:
        last_activity_str = datetime.fromtimestamp(last_activity, tz).strftime("%Y-%m-%d %H:%M:%S")

    user_id = session.get("user_id") or session.get("pending_user_id")
    mfa_enabled = is_mfa_enabled(user_id) if user_id else False

    last_login_event = last_login.get(username)
    if last_login_event:
        last_login_event["time_str"] = last_login_event["time"]

    return render_template(
        "profile.html",
        username=username,
        name=name,
        email=email,
        role=role,
        is_admin=is_admin,
        device=device,
        device_type=device_type,
        trusted_device=trusted_device,
        login_time=login_time_str,
        last_activity=last_activity_str,
        mfa_enabled=mfa_enabled,
        last_login_event=last_login_event,
    )


@app.route("/settings")
def settings():
    username = session.get("username")
    if not username:
        return redirect("/login")

    return render_template("settings.html")


@app.route("/settings/password", methods=["GET", "POST"])
def settings_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    user = get_user_by_username(username)

    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 1. Validate old password
        if not check_password_hash(user["password_hash"], old_password):
            return render_template("settings_password.html", error="Current password is incorrect")

        # 2. Validate new passwords match
        if new_password != confirm_password:
            return render_template("settings_password.html", error="New passwords do not match")

        # 3. Validate password strength (simple check)
        if len(new_password) < 8:
            return render_template("settings_password.html", error="Password must be at least 8 characters")

        # 4. Update password
        new_hash = generate_password_hash(new_password)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hash, username))
        conn.commit()
        conn.close()

        return render_template("settings_password.html", success="Password updated successfully")

    return render_template("settings_password.html")


@app.route("/settings/mfa")
def settings_mfa():
    return render_template("settings_mfa.html")

@app.route("/settings/recovery")
def settings_recovery():
    return render_template("settings_recovery.html")

@app.route("/settings/devices")
def settings_devices():
    if "user_id" not in session:
        return redirect("/login")

    from database import get_trusted_devices

    user_id = session["user_id"]
    devices = get_trusted_devices(user_id)

    return render_template("settings_devices.html", devices=devices)

@app.route("/settings/devices/trust", methods=["POST"])
def trust_this_device():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    device_fp = session.get("device_fingerprint")
    ip = get_client_ip()
    gps = get_gps_location()
    place = reverse_geocode(gps.get("lat"), gps.get("lon"))
    device = get_device_info()

    auto_name = f"{device.get('browser')} on {device.get('os')}"

    from database import record_trusted_device

    record_trusted_device(
        user_id=user_id,
        fingerprint=device_fp,
        auto_name=auto_name,
        ip=ip,
        location=place
    )

    return redirect("/settings/devices")

# ------------------------------------------------------------
# RENAME TRUSTED DEVICE
# ------------------------------------------------------------
@app.route("/settings/devices/rename/<int:device_id>", methods=["POST"])
def rename_trusted_device(device_id):
    if "user_id" not in session:
        return redirect("/login")

    new_name = request.form.get("new_name", "").strip()

    if new_name:
        from database import update_trusted_device_name
        update_trusted_device_name(device_id, new_name)

    return redirect("/settings/devices")


# ------------------------------------------------------------
# REMOVE TRUSTED DEVICE
# ------------------------------------------------------------
@app.route("/settings/devices/remove/<int:device_id>", methods=["POST"])
def remove_trusted_device_route(device_id):
    if "user_id" not in session:
        return redirect("/login")

    from database import remove_trusted_device
    remove_trusted_device(device_id)

    return redirect("/settings/devices")
# ------------------------------------------------------------
# REMOVE ALL TRUSTED DEVICES
# ------------------------------------------------------------
@app.route("/settings/devices/remove_all", methods=["POST"])
def remove_all_trusted_devices_route():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]

    from database import remove_all_trusted_devices
    remove_all_trusted_devices(user_id)

    return redirect("/settings/devices")

@app.route("/settings/sessions")
def settings_sessions():
    if "user_id" not in session:
        return redirect("/login")

    # Update last activity for the current session
    update_last_activity()

    user_id = session["user_id"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, session_id, ip, location, user_agent, device_type,
               login_time, last_activity, is_active
        FROM user_sessions
        WHERE user_id = ?
        ORDER BY last_activity DESC
    """, (user_id,))
    sessions = cur.fetchall()
    conn.close()

    current_session = session.get("session_id")

    return render_template(
        "settings_sessions.html",
        sessions=sessions,
        current_session=current_session
    )

@app.route("/settings/sessions/logout/<session_id>")
def logout_session(session_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE user_sessions
        SET is_active = 0
        WHERE session_id = ? AND user_id = ?
    """, (session_id, session["user_id"]))
    conn.commit()
    conn.close()

    return redirect("/settings/sessions")

@app.route("/settings/sessions/logout_all")
def logout_all_sessions():
    if "user_id" not in session:
        return redirect("/login")

    current = session.get("session_id")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE user_sessions
        SET is_active = 0
        WHERE user_id = ? AND session_id != ?
    """, (session["user_id"], current))
    conn.commit()
    conn.close()

    return redirect("/settings/sessions")


@app.route("/settings/history")
def settings_history():
    return render_template("settings_history.html")

@app.route("/update_gps", methods=["POST"])
def update_gps():
    data = request.get_json()
    lat = data.get("lat")
    lon = data.get("lon")

    if lat and lon:
        session["gps_lat"] = lat
        session["gps_lon"] = lon

        try:
            url = f"https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=json"
            resp = requests.get(url, timeout=2, headers={"User-Agent": "Mozilla/5.0"})

            if resp.status_code == 200 and "application/json" in resp.headers.get("Content-Type", ""):
                info = resp.json()
                address = info.get("display_name", "Unknown")
            else:
                address = "Unknown"

        except Exception as e:
            app.logger.error(f"GPS reverse geocode failed: {e}")
            address = "Unknown"

        # ⭐ REQUIRED FIX — store address in session
        session["gps_address"] = address

    return "OK", 200


@app.template_filter("fmt_time")
def fmt_time(value):
    """
    Smart timestamp formatter:
    - Accepts UNIX timestamps (int/float)
    - Accepts string timestamps ("2026-04-21 19:21:34")
    - Returns clean formatted output
    """
    try:
        # Case 1: value is already a datetime object
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")

        # Case 2: value is a UNIX timestamp (int/float)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")

        # Case 3: value is a string timestamp
        if isinstance(value, str):
            # Try parsing your NY format first
            try:
                dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass

            # Try ISO format
            try:
                dt = datetime.fromisoformat(value)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except:
                pass

            # If all parsing fails, return the string as-is
            return value

        # Unknown type → return as-is
        return value

    except Exception as e:
        app.logger.error(f"fmt_time failed: {e}")
        return value

# ---------------------------------------------------------
# 🚨 BLOCKED PAGE
# ---------------------------------------------------------
@app.route("/blocked")
def blocked_page():
    resp = make_response(render_template("blocked.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate admin credentials
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:

            # Admin session is isolated via admin_* keys
            session["admin_authenticated"] = True
            session["admin_username"] = username
            session["admin_is_admin"] = True
            session["admin_login_time"] = time.time()
            session["admin_last_activity"] = time.time()

            # Hashed fingerprint (correct)
            admin_fp = get_device_fingerprint()
            session["admin_device_fingerprint"] = admin_fp

            # JWT receives string fingerprint (correct)
            token = generate_jwt(
                username="admin",
                role="admin",
                device_fp=admin_fp,
                ip=get_client_ip(),
            )
            session["admin_jwt"] = token

            return redirect("/admin/security")

        # Wrong credentials
        return "Invalid admin credentials", 403

    # GET request → render login page
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Login</title>
        <style>
            body {
                margin: 0;
                padding: 0;
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                background: url('https://images.unsplash.com/photo-1555949963-aa79dcee981c') no-repeat center center/cover;
                font-family: Arial, sans-serif;
                color: #e0e0e0;
                backdrop-filter: blur(3px);
            }
            .login-box {
                background: rgba(0, 0, 0, 0.75);
                padding: 40px;
                width: 350px;
                border-radius: 12px;
                box-shadow: 0 0 20px rgba(0,255,255,0.3);
                border: 1px solid rgba(0,255,255,0.4);
                text-align: center;
            }
            .login-box h2 {
                color: cyan;
                margin-bottom: 25px;
                font-size: 26px;
                letter-spacing: 1px;
            }
            .login-box input {
                width: 90%;
                padding: 12px;
                margin: 10px 0;
                border-radius: 6px;
                border: none;
                outline: none;
                font-size: 16px;
            }
            .login-box button {
                width: 95%;
                padding: 12px;
                margin-top: 15px;
                background: cyan;
                border: none;
                border-radius: 6px;
                font-size: 18px;
                cursor: pointer;
                font-weight: bold;
            }
            .login-box button:hover {
                background: #00e0e0;
            }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>Admin Login</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Admin Username" required>
                <input type="password" name="password" placeholder="Admin Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type")

    if grant_type == "authorization_code":
        code = request.form.get("code")
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")
        redirect_uri = request.form.get("redirect_uri")

        # PKCE: code_verifier is REQUIRED
        code_verifier = request.form.get("code_verifier")
        if not code_verifier:
            return {
                "error": "invalid_request",
                "error_description": "PKCE code_verifier required",
            }, 400

        client = OAUTH_CLIENTS.get(client_id)
        if not client or client["client_secret"] != client_secret:
            return {"error": "invalid_client"}, 401

        data = AUTH_CODES.get(code)
        if not data:
            return {"error": "invalid_grant"}, 400

        if data["redirect_uri"] != redirect_uri:
            return {"error": "invalid_grant"}, 400

        if time.time() > data["expires_at"]:
            del AUTH_CODES[code]
            return {"error": "expired_code"}, 400

        # PKCE validation
        expected_challenge = data.get("code_challenge")
        method = data.get("code_challenge_method")

        if not expected_challenge or method != "S256":
            del AUTH_CODES[code]
            return {
                "error": "invalid_grant",
                "error_description": "PKCE data missing or invalid",
            }, 400

        computed_challenge = pkce_challenge_from_verifier(code_verifier)

        if computed_challenge != expected_challenge:
            del AUTH_CODES[code]
            return {
                "error": "invalid_grant",
                "error_description": "PKCE verification failed",
            }, 400

        # PKCE passed, code is now single-use
        del AUTH_CODES[code]

        username = data["user"]
        scopes = data["scope"]

        # Fetch user from SQLite
        user = get_user_by_username(username)
        if not user:
            return {"error": "server_error", "error_description": "User not found"}, 500

        # Access Token
        access_token = generate_jwt(
            username=username,
            role=user["role"],
            device_fp=None,
            ip=None,
        )

        # ID Token
        id_token_payload = {
            "iss": "http://localhost:5000",
            "sub": str(user["id"]),
            "aud": client_id,
            "iat": int(time.time()),
            "exp": int(time.time()) + 900,
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "device": "unknown",
            "ip": "unknown",
        }

        id_token = jwt.encode(id_token_payload, JWT_SECRET, algorithm="HS256")

        # Refresh Token
        refresh_token = uuid.uuid4().hex
        REFRESH_TOKENS[refresh_token] = {
            "user": username,
            "client_id": client_id,
            "scope": scopes,
            "expires_at": time.time() + REFRESH_TOKEN_LIFETIME,
        }

        return {
            "access_token": access_token,
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_LIFETIME,
            "refresh_token": refresh_token,
            "scope": " ".join(scopes),
        }

    return {"error": "unsupported_grant_type"}, 400

@app.route("/admin/unblock/<ip>", methods=["POST"])
@admin_required
def admin_unblock(ip):
    if ip in blocked_ips:
        del blocked_ips[ip]

    if ip in ip_behavior:
        del ip_behavior[ip]

    if ip in request_log:
        request_log[ip] = []

    return redirect("/admin/security")


@app.route("/admin/users/create", methods=["GET", "POST"])
@admin_required
def admin_create_user():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "user")
        password = request.form.get("password", "").strip()
        status = request.form.get("status", "active")
        mfa_enabled = int(request.form.get("mfa_enabled", 0))
        provider = request.form.get("provider", "Normal")

        if not username:
            return render_template("admin_user_create.html", error="Username is required")

        if provider == "Normal" and not password:
            return render_template("admin_user_create.html", error="Password required for Local users")

        existing = get_user_by_username(username)
        if existing:
            return render_template("admin_user_create.html", error="Username already exists")

        if provider == "Normal":
            password_hash = generate_password_hash(password)
        else:
            password_hash = ""

        create_user(
            username=username,
            email=email or f"{username}@example.com",
            name=name or username,
            password_hash=password_hash,
            role=role,
        )

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            UPDATE users SET
                status = ?,
                mfa_enabled = ?,
                last_provider = ?
            WHERE username = ?
        """, (status, mfa_enabled, provider, username))
        conn.commit()
        conn.close()

        return redirect("/admin/users")

    return render_template("admin_user_create.html")
# ------------------------------
# ADMIN: EDIT USER
# ------------------------------
@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    row = get_user_by_id(user_id)
    if not row:
        return "User not found", 404

    # Convert sqlite3.Row → dict for safe .get() in template
    user = dict(row)

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        role = request.form.get("role", "user")
        status = request.form.get("status", "active")
        mfa_enabled = int(request.form.get("mfa_enabled", 0))
        new_password = request.form.get("new_password", "").strip()

        update_user(user_id, name, email, role, status, mfa_enabled)

        if new_password:
            password_hash = generate_password_hash(new_password)
            update_user_password(user_id, password_hash)

        return redirect("/admin/users")

    return render_template("admin_user_edit.html", user=user)
# ------------------------------
# ADMIN: DELETE USER
# ------------------------------
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    delete_user(user_id)
    return redirect("/admin/users")
# ------------------------------
# ADMIN SECURITY DASHBOARD
# ------------------------------
@app.route("/admin/security")
@admin_required
def admin_security():
    # Convert events to dicts for safe JSON + Jinja access
    events = [dict(e) for e in security_events]

    return render_template(
        "admin_security.html",
        security_events=events,
        ip_behavior=ip_behavior,
        blocked_ips=blocked_ips,
    )

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_username", None)
    session.pop("admin_is_admin", None)
    session.pop("admin_jwt", None)
    session.pop("admin_device_fingerprint", None)
    session.pop("admin_last_activity", None)
    session.pop("admin_login_time", None)

    return redirect("/admin/login")

# ------------------------------
# ADMIN USER DASHBOARD
# ------------------------------
@app.route("/admin/users")
@admin_required
def admin_users():
    db_users = get_all_users()
    user_data = []

    for row in db_users:
        u = dict(row)  # Convert sqlite3.Row → dict

        username = u.get("username")
        last = last_login.get(username, {})
        history = login_history.get(username, [])

        # Safe access for last login fields
        last_time = last.get("time")
        last_ip = last.get("ip")
        last_location = last.get("location")
        last_provider = last.get("provider")

        last_device = last.get("device") or "Unknown"
        last_os = last.get("os") or "Unknown"
        last_browser = last.get("browser") or "Unknown"
        # Compute risk score
        risk = 0
        if history:
            if len(history) > 5:
                risk += 5
            if last_location and "Unknown" in last_location:
                risk += 10

        user_data.append({
            "id": u.get("id"),
            "username": username,
            "email": u.get("email"),
            "name": u.get("name"),
            "role": u.get("role"),

            # Default status = active
            "status": u.get("status", "active"),

            "last_login": last_time,
            "last_ip": last_ip,
            "last_location": last_location,
            "last_provider": last_provider,

            # MFA
            "mfa_enabled": is_mfa_enabled(u.get("id")),

            # Device info
            "last_device": last_device,
            "last_os": last_os,
            "last_browser": last_browser,

            "risk": risk,
            "history": history,
        })

    return render_template("admin_users.html", users=user_data)

@app.route("/admin/export/logs.json")
def export_all_logs_json():
    data = {
        "security_events": security_events,
        "login_history": login_history,
        "last_login": last_login,
    }
    return jsonify(data)

@app.route("/admin/export/security_events.json")
def export_security_events_json():
    return jsonify(security_events)

@app.route("/admin/export/login_history.json")
def export_login_history_json():
    return jsonify(login_history)

@app.route("/admin/export/logs.csv")
def export_all_logs_csv():
    output = io.StringIO()
    rows = []

    # Security events
    for event in security_events:
        row = {"type": "security_event"}
        row.update(event)
        rows.append(row)

    # Login history
    for username, events in login_history.items():
        for event in events:
            row = {"type": "login_event", "username": username}
            row.update(event)
            rows.append(row)

    if not rows:
        return "No logs available", 404

    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=all_logs.csv"}
    )

@app.route("/admin/export/security_events.csv")
def export_security_events_csv():
    if not security_events:
        return "No security events available", 404

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=security_events[0].keys())
    writer.writeheader()
    writer.writerows(security_events)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_events.csv"}
    )

@app.route("/admin/export/login_history.csv")
def export_login_history_csv():
    output = io.StringIO()
    rows = []

    for username, events in login_history.items():
        for event in events:
            row = {"username": username}
            row.update(event)
            rows.append(row)

    if not rows:
        return "No login history available", 404

    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=login_history.csv"}
    )


@app.route("/oauth/authorize", methods=["GET", "POST"])
def oauth_authorize():
    client_id = request.args.get("client_id")
    redirect_uri = request.args.get("redirect_uri")
    scope = request.args.get("scope", "")
    state = request.args.get("state", "")

    # PKCE parameters (REQUIRED)
    code_challenge = request.args.get("code_challenge")
    code_challenge_method = request.args.get("code_challenge_method")

    if not code_challenge or not code_challenge_method:
        return "PKCE required: missing code_challenge or code_challenge_method", 400

    if code_challenge_method != "S256":
        return "Only S256 PKCE method supported", 400

    client = OAUTH_CLIENTS.get(client_id)
    if not client:
        return "Invalid client_id", 400

    if redirect_uri not in client["redirect_uris"]:
        return "Invalid redirect_uri", 400

    requested_scopes = scope.split()

    for s in requested_scopes:
        if s not in client["allowed_scopes"]:
            return "Invalid scope", 400

    if request.method == "GET":
        username = session.get("admin_username") or session.get("user_username")
        return render_template(
            "oauth_consent.html",
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=requested_scopes,
            state=state,
            username=username,
        )

    if request.form.get("approve") != "yes":
        return redirect(f"{redirect_uri}?error=access_denied&state={state}")

    code = uuid.uuid4().hex
    AUTH_CODES[code] = {
        "user": session.get("admin_username") or session.get("user_username"),
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": requested_scopes,
        "expires_at": time.time() + OAUTH_CODE_LIFETIME,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }

    return redirect(f"{redirect_uri}?code={code}&state={state}")


@app.route("/admin/jwt-viewer")
@admin_required
def jwt_viewer():
    token = session.get("admin_jwt")
    decoded = validate_jwt(token) if token else None
    return render_template("jwt_viewer.html", token=token, decoded=decoded)


PATTERNS = {
    "xss": ["<script", "onerror=", "javascript:"],
    "sql": ["' OR 1=1", "UNION SELECT", "DROP TABLE", "--"],
    "path": ["../", "/etc/passwd", "C:\\windows"],
}


def calculate_risk_score(ip, form_data):
    score = 0
    details = []
    matched = set()

    for field, value in form_data.items():
        text = str(value).lower()
        for category, patterns in PATTERNS.items():
            for p in patterns:
                if p.lower() in text:
                    matched.add((category, p))

    for category, p in matched:
        if category == "xss":
            score += 30
            details.append(f"XSS pattern detected: {p}")
        elif category == "sql":
            score += 40
            details.append(f"SQL injection pattern detected: {p}")
        elif category == "path":
            score += 20
            details.append(f"Path traversal pattern detected: {p}")

    if score > 100:
        score = 100

    return score, details

def log_event(event_type, severity, ip, details=None):
    now_ny = datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d %H:%M:%S")

    loc = get_ip_location(ip)
    ip_location_label = loc["location"]
    isp = loc.get("isp")
    asn = loc.get("asn")

    gps_lat = session.get("gps_lat")
    gps_lon = session.get("gps_lon")

    if gps_lat and gps_lon:
        lat = gps_lat
        lon = gps_lon
        location = session.get("gps_address") or ip_location_label
    else:
        location = ip_location_label
        lat = loc["lat"]
        lon = loc["lon"]

    login_provider = session.get("login_provider")

    if login_provider == "Azure":
        provider = "Azure"
        username = session.get("email") or session.get("username") or "Unknown"

    elif login_provider == "Auth0":
        provider = "Auth0"
        username = session.get("email") or session.get("username") or "Unknown"

    elif login_provider == "Normal":
        provider = "Normal"
        username = session.get("username") or "Unknown"

    elif login_provider == "Admin":
        provider = "Admin"
        username = session.get("admin") or "Admin"

    else:
        # Fallback (rare)
        provider = "System"
        username = session.get("username") or session.get("email") or "N/A"

    behavior = ip_behavior.get(ip, {})
    request_count = behavior.get("request_count", 0)
    suspicious_count = behavior.get("suspicious_count", 0)
    risk_score = behavior.get("risk_score", 0)
    risk = behavior.get("risk", "normal")

    device_info = get_device_info()
    device = device_info.get("device", "Unknown device")
    os_name = device_info.get("os", "Unknown OS")
    browser = device_info.get("browser", "Unknown browser")

 
    clean_details = details or f"{username} logged in via {provider} from {location}"

    event = {
        "type": event_type,
        "severity": severity,
        "ip": ip,
        "details": clean_details,
        "time": now_ny,
        "location": location,
        "lat": lat,
        "lon": lon,
        "username": username,
        "provider": provider,
        "mfa_enabled": session.get("mfa_enabled", False),
        "device": device,
        "os": os_name,
        "browser": browser,
        "isp": isp,
        "asn": asn,
        "risk_score": risk_score,
        "suspicious_count": suspicious_count,
        "requests": request_count,
        "status": risk,
    }

    print("🔥 SECURITY EVENT ADDED:", event)

    security_events.append(event)
    if len(security_events) > 20:
        security_events.pop(0)

    forward_to_splunk(event)

ip_behavior = {}  # stores behavior score, history, last seen, etc.

def init_ip(ip):
    if ip not in ip_behavior:
        ip_behavior[ip] = {
            "request_count": 0,
            "suspicious_count": 0,
            "risk_score": 0,
            "risk": "normal",
            "last_seen": time.time(),
        }

def update_behavior(ip, severity, reason):
    data = ip_behavior[ip]

    if severity == "green":
        data["request_count"] += 1
        data["risk_score"] = max(0, data["risk_score"] - 5)

    elif severity == "yellow":
        data["suspicious_count"] += 1
        data["risk_score"] += 10

    elif severity == "red":
        data["suspicious_count"] += 1
        data["risk_score"] += 25

    data["last_seen"] = time.time()

    if data["risk_score"] < 30:
        data["risk"] = "normal"
    elif data["risk_score"] < 60:
        data["risk"] = "suspicious"
    else:
        data["risk"] = "hostile"

    return data["risk"]

# Phase 8: Auto-Prevention Engine
blocked_ips = {}  # ip: unblock_time
BLOCK_DURATION = 300

def is_blocked(ip):
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]
    return False

def detect_suspicious_input(form_data):
    suspicious_patterns = [
        "<script",
        "onerror",
        "drop table",
        "select *",
        "' or 1=1",
        "--",
        ";--",
        "<?php",
        "<img",
    ]
    text = " ".join(str(v).lower() for v in form_data.values())
    return any(p in text for p in suspicious_patterns)

def sanitize_input(form_data):
    cleaned = {}
    dangerous = ["<", ">", "'", '"', ";", "--", "<?", "?>"]

    for key, value in form_data.items():
        text = str(value)
        original = text

        for d in dangerous:
            text = text.replace(d, "")

        cleaned[key] = text

        if text != original:
            client_ip = get_client_ip()
            log_event("sanitized", "yellow", client_ip, f"Removed dangerous characters from '{key}'")

    return cleaned


def pkce_challenge_from_verifier(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def generate_jwt(username, role, device_fp, ip):
    payload = {
        "sub": username,
        "username": username,          # for /oauth/userinfo
        "role": role,
        "device_fp": device_fp,        # consistent naming
        "ip": ip,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXPIRATION),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return token

def validate_jwt(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return decoded
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_security_status(ip, form_data):
    init_ip(ip)
    now = time.time()
    window = 60

    suspicious = detect_suspicious_input(form_data)
    form_data = sanitize_input(form_data)

    score, details = calculate_risk_score(ip, form_data)
    ip_behavior[ip]["risk_score"] = score

    if score > 0:
        suspicious = True
        for d in details:
            severity = "red" if score > 50 else "yellow"
            log_event("attack", severity, ip, d)

    request_log[ip] = [t for t in request_log[ip] if now - t < window]
    request_log[ip].append(now)

    if suspicious:
        risk = update_behavior(ip, "red", "Suspicious input")
        if risk == "hostile":
            blocked_ips[ip] = time.time() + BLOCK_DURATION
            log_event("attack", "red", ip, "IP Blocked (hostile behavior)")
            return "red"
        return "red"

    log_event("system", "green", ip, "Normal request")
    update_behavior(ip, "green", "Normal")
    return "green"

def get_jwks():
    resp = requests.get(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json", timeout=5)
    resp.raise_for_status()
    return resp.json()

def get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        return None

    parts = auth.split()

    if parts[0].lower() != "bearer":
        return None
    elif len(parts) == 1:
        return None
    elif len(parts) > 2:
        return None

    return parts[1]


def verify_jwt(token):
    jwks = get_jwks()
    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }

    if rsa_key:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/"
        )
        return payload

    return None


def requires_scope(required_scope, payload):
    if "scope" in payload:
        token_scopes = payload["scope"].split()
        return required_scope in token_scopes
    return False


@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

@app.route("/api/secure-data")
def secure_data():
    token = get_token_auth_header()
    if not token:
        return jsonify({"error": "Authorization header missing"}), 401

    try:
        payload = verify_jwt(token)
    except Exception as e:
        app.logger.error(f"JWT verification failed: {e}")
        return jsonify({"error": "Invalid token"}), 401

    if not requires_scope("read:data", payload):
        return jsonify({"error": "Insufficient scope"}), 403

    return jsonify({"message": "Secure data accessed", "payload": payload})


@app.route("/", methods=["GET", "POST"])
@login_required
def dashboard():
    tool = "bmi"
    result = {}
    chart_data = {}
    security_status = "green"

    # Suspicious session warning banner
    warning = None
    if session.pop("suspicious_logout", False):
        warning = "⚠ Suspicious activity detected on your last session. Please review your security logs."

    ip = get_client_ip()
    now = time.time()

    # Ensure IP behavior is initialized
    init_ip(ip)

    # Auto-reset request count every 60 seconds
    if now - ip_behavior[ip]["last_seen"] > 60:
        ip_behavior[ip]["request_count"] = 0

    # Count POST requests only
    if request.method == "POST":
        ip_behavior[ip]["request_count"] += 1

    ip_behavior[ip]["last_seen"] = now

    # Traffic control (throttling + blocking + 429)
    request_count = ip_behavior[ip]["request_count"]

    THROTTLE_LIMIT = 30  # slow down only
    RATE_LIMIT = 60      # block + 429

    # Throttle
    if THROTTLE_LIMIT < request_count <= RATE_LIMIT:
        time.sleep(2)
        log_event("traffic", "yellow", ip, f"Throttled: {request_count} req/min")
        ip_behavior[ip]["risk"] = "suspicious"

    # Rate limit exceeded → block
    if request_count > RATE_LIMIT:
        blocked_ips[ip] = time.time() + BLOCK_DURATION
        log_event("traffic", "red", ip, f"Rate limit exceeded: {request_count} req/min — IP BLOCKED")
        ip_behavior[ip]["risk"] = "hostile"
        return make_response("Too Many Requests — You are temporarily blocked", 429)

    # Blocked IP check + auto-unblock
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return render_template("blocked.html", ip=ip)
        else:
            del blocked_ips[ip]
            log_event("system", "green", ip, "IP Unblocked (cooldown expired)")
            ip_behavior[ip]["risk"] = "normal"

    # Process POST request (BMI, etc.)
    if request.method == "POST":
        tool = request.form.get("tool_type", "bmi")

        # Attack detection only (Phase 7 + 8)
        security_status = get_security_status(ip, request.form.to_dict())

        try:
            if tool == "bmi":
                age = int(request.form["age"])
                weight = float(request.form["weight"])
                h_ft = int(request.form["height_ft"])
                h_in = int(request.form["height_in"])
                total_in = h_ft * 12 + h_in
                bmi = round((weight * 703) / (total_in * total_in), 2)

                if bmi < 18.5:
                    cat, color = "Underweight", "#3498db"
                elif bmi < 25:
                    cat, color = "Normal", "#2ecc71"
                elif bmi < 30:
                    cat, color = "Overweight", "#f1c40f"
                else:
                    cat, color = "Obese", "#e74c3c"

                result = {"bmi": bmi, "category": cat, "color": color}
                chart_data = {
                    "labels": ["Underweight", "Normal", "Overweight", "Obese"],
                    "values": [18.5, 6.4, 4.9, 5],
                }

            elif tool == "calories":
                age = int(request.form["age"])
                weight = float(request.form["weight"])
                h_ft = int(request.form["height_ft"])
                h_in = int(request.form["height_in"])
                gender = request.form["gender"]
                activity = request.form["activity"]

                total_cm = (h_ft * 12 + h_in) * 2.54
                weight_kg = weight * 0.453592

                if gender == "male":
                    bmr = 10 * weight_kg + 6.25 * total_cm - 5 * age + 5
                else:
                    bmr = 10 * weight_kg + 6.25 * total_cm - 5 * age - 161

                factors = {
                    "sedentary": 1.2,
                    "light": 1.375,
                    "moderate": 1.55,
                    "active": 1.725,
                    "very_active": 1.9,
                }
                tdee = round(bmr * factors.get(activity, 1.2))

                result = {"bmr": round(bmr), "tdee": tdee}
                chart_data = {
                    "labels": ["BMR", "TDEE"],
                    "values": [round(bmr), tdee],
                }

            elif tool == "burn":
                activity = request.form["activity"]
                weight = float(request.form["weight"])
                met_values = {
                    "sedentary": 1.3,
                    "light": 2.5,
                    "moderate": 4.5,
                    "active": 6.0,
                    "very_active": 8.0,
                }
                met = met_values.get(activity, 1.3)
                weight_kg = weight * 0.453592
                per_hour = round(met * weight_kg, 1)

                result = {"per_hour": per_hour, "activity": activity}
                chart_data = {
                    "labels": list(met_values.keys()),
                    "values": [round(met_values[a] * weight_kg, 1) for a in met_values],
                }

            elif tool == "stress":
                mood = int(request.form["mood"])
                workload = int(request.form["workload"])
                sleep = int(request.form["sleep"])

                stress_score = mood * 2 + workload * 3 - sleep
                stress_score = max(0, min(100, stress_score))

                if stress_score < 30:
                    level, color = "Low", "#2ecc71"
                elif stress_score < 60:
                    level, color = "Moderate", "#f1c40f"
                else:
                    level, color = "High", "#e74c3c"

                result = {"score": stress_score, "level": level, "color": color}
                chart_data = {
                    "labels": ["Mood", "Workload", "Sleep"],
                    "values": [mood, workload, sleep],
                }

            elif tool == "sleep":
                hours = float(request.form["hours"])
                interruptions = int(request.form["interruptions"])
                consistency = int(request.form["consistency"])

                score = hours * 10 - interruptions * 5 + consistency * 2
                score = max(0, min(100, score))

                if score < 40:
                    level, color = "Poor", "#e74c3c"
                elif score < 70:
                    level, color = "Fair", "#f1c40f"
                else:
                    level, color = "Good", "#2ecc71"

                result = {"score": score, "level": level, "color": color}
                chart_data = {
                    "labels": ["Hours", "Interruptions", "Consistency"],
                    "values": [hours, interruptions, consistency],
                }

            elif tool == "hydration":
                intake = float(request.form["intake"])
                weight = float(request.form["weight"])
                required = round(weight * 0.5, 1)
                ratio = intake / required if required > 0 else 0

                if ratio < 0.7:
                    level, color = "Low", "#e74c3c"
                elif ratio < 1.1:
                    level, color = "Optimal", "#2ecc71"
                else:
                    level, color = "High", "#f1c40f"

                result = {
                    "intake": intake,
                    "required": required,
                    "level": level,
                    "color": color,
                }
                chart_data = {
                    "labels": ["Intake", "Required"],
                    "values": [intake, required],
                }

            elif tool == "heart":
                age = int(request.form["age"])
                bmi = float(request.form["bmi"])
                activity = request.form["activity"]

                base = age + bmi
                if activity in ["active", "very_active"]:
                    base -= 10

                risk = max(0, min(100, base))

                if risk < 40:
                    level, color = "Low", "#2ecc71"
                elif risk < 70:
                    level, color = "Moderate", "#f1c40f"
                else:
                    level, color = "High", "#e74c3c"

                result = {"risk": risk, "level": level, "color": color}
                chart_data = {
                    "labels": ["Risk"],
                    "values": [risk],
                }

            elif tool == "wellness":
                bmi = float(request.form["bmi"])
                stress = int(request.form["stress"])
                sleep = int(request.form["sleep"])
                hydration = int(request.form["hydration"])

                score = 100
                if bmi < 18.5 or bmi > 30:
                    score -= 15
                score -= stress * 0.5
                score += sleep * 0.5
                score += hydration * 0.3
                score = max(0, min(100, score))

                if score < 40:
                    level, color = "Poor", "#e74c3c"
                elif score < 70:
                    level, color = "Fair", "#f1c40f"
                else:
                    level, color = "Good", "#2ecc71"

                result = {"score": score, "level": level, "color": color}
                chart_data = {
                    "labels": ["BMI Impact", "Stress", "Sleep", "Hydration"],
                    "values": [bmi, stress, sleep, hydration],
                }

        except (ValueError, KeyError):
            result = {"error": "Invalid input. Please check your values."}

        # Clear login alerts after first successful interaction
        session.pop("user_login_alerts", None)

    username = session.get("username")
    login_provider = session.get("login_provider")

    user_id = session.get("user_id") or session.get("pending_user_id")
    mfa_enabled = is_mfa_enabled(user_id) if user_id else False

    last_login_event = last_login.get(username)
    if last_login_event:
        tz = ZoneInfo("America/New_York")
        last_login_event["time_str"] = last_login_event["time"]

    user_history = login_history.get(username, [])

    return render_template(
        "index.html",
        tool=tool,
        warning=warning,
        result=result,
        chart_data=chart_data,
        security_status=security_status,
        login_provider=login_provider,
        mfa_enabled=mfa_enabled,
        last_login_event=last_login_event,
        login_history=user_history,
    )

@app.route("/save_gps", methods=["POST"])
def save_gps():
    data = request.json
    session["gps_lat"] = data.get("lat")
    session["gps_lon"] = data.get("lon")
    session["gps_accuracy"] = data.get("accuracy")
    return "OK", 200

@app.route("/oauth/userinfo", methods=["GET"])
def userinfo():
    # Extract access token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return {"error": "invalid_request"}, 400

    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or not parts[1]:
        return {"error": "invalid_request"}, 400

    access_token = parts[1]

    # Decode JWT
    try:
        payload = jwt.decode(access_token, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        app.logger.error(f"JWT decode failed: {e}")
        return {"error": "invalid_token"}, 401

    username = payload.get("username")
    if not username:
        return {"error": "invalid_token"}, 401

    # Fetch user from SQLite
    user = get_user_by_username(username)
    if not user:
        return {"error": "invalid_token"}, 401

    # Build OIDC-compliant UserInfo response
    return {
        "sub": str(user["id"]),
        "name": user["name"],
        "email": user["email"],
        "preferred_username": user["username"],
        "role": user["role"],
        "device": payload.get("device_fp", "unknown"),
        "ip": payload.get("ip", "unknown"),
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)  # nosec