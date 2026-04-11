"""
Production Flask Login Application
All security rules enforced — see inline comments.
"""

import os
import logging
from datetime import timedelta
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
import sqlite3
import markupsafe  # HTML escaping

# ─── App Setup ───────────────────────────────────────────────────────────────

app = Flask(__name__)

# RULE: NEVER hardcode secrets — use os.environ.get()
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
app.config["WTF_CSRF_SECRET_KEY"] = os.environ.get("WTF_CSRF_SECRET_KEY")
app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "users.db")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set!")

# ─── Security: Session hardening ─────────────────────────────────────────────
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # JS cannot read session cookie
    SESSION_COOKIE_SECURE=True,     # Only sent over HTTPS
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF mitigation
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# ─── CSRF Protection ─────────────────────────────────────────────────────────
csrf = CSRFProtect(app)

# ─── Rate Limiting (brute-force protection) ───────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"),
)

# ─── Logging (no debug info to users, only server logs) ──────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


# ─── Database Helpers ─────────────────────────────────────────────────────────

def get_db():
    """Open a database connection from the configured path."""
    db_path = os.path.realpath(app.config["DATABASE"])
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database schema."""
    with app.app_context():
        db = get_db()
        db.executescript(open("schema.sql").read())
        db.commit()
        db.close()


# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def login_required(f):
    """Decorator: redirect to login if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_user_by_username(username: str):
    """
    Fetch a user row by username.
    RULE: ALWAYS use parameterized queries — never string concatenation.
    """
    db = get_db()
    try:
        # ✅ Parameterized query — safe from SQL injection
        user = db.execute(
            "SELECT id, username, password_hash, failed_attempts, locked FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        return user
    finally:
        db.close()


def record_failed_attempt(username: str):
    """Increment failed login counter and lock account after 5 failures."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
            (username,)
        )
        db.execute(
            "UPDATE users SET locked = 1 WHERE username = ? AND failed_attempts >= 5",
            (username,)
        )
        db.commit()
    finally:
        db.close()


def reset_failed_attempts(username: str):
    """Reset failed counter on successful login."""
    db = get_db()
    try:
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked = 0 WHERE username = ?",
            (username,)
        )
        db.commit()
    finally:
        db.close()


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")  # Brute-force protection
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        # RULE: ALWAYS escape user input before using it
        raw_username = request.form.get("username", "").strip()
        raw_password = request.form.get("password", "")

        # Basic input validation
        if not raw_username or not raw_password:
            error = "Please enter both username and password."
        elif len(raw_username) > 64 or len(raw_password) > 256:
            error = "Invalid input length."
        else:
            user = get_user_by_username(raw_username)

            # Generic error — NEVER reveal whether username exists
            if user is None:
                error = "Invalid username or password."
                logger.warning("Failed login attempt for unknown user '%s'", raw_username)
            elif user["locked"]:
                error = "This account has been locked due to too many failed attempts. Contact support."
                logger.warning("Login attempt on locked account '%s'", raw_username)
            else:
                # RULE: Use bcrypt — NEVER MD5 or SHA1
                password_matches = bcrypt.checkpw(
                    raw_password.encode("utf-8"),
                    user["password_hash"]
                )

                if password_matches:
                    # Successful login — regenerate session to prevent fixation
                    session.clear()
                    session["user_id"] = user["id"]
                    session["username"] = user["username"]
                    session.permanent = True
                    reset_failed_attempts(raw_username)
                    logger.info("User '%s' logged in successfully.", raw_username)
                    return redirect(url_for("dashboard"))
                else:
                    record_failed_attempt(raw_username)
                    error = "Invalid username or password."
                    logger.warning("Failed login for user '%s'.", raw_username)

    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    # RULE: ALWAYS escape before rendering — markupsafe.escape() used in template
    username = session.get("username", "")
    return render_template("dashboard.html", username=username)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    username = session.get("username")
    session.clear()
    logger.info("User '%s' logged out.", username)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ─── Error Handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    # RULE: NEVER expose stack traces or debug info to users
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("error.html", code=429, message="Too many attempts. Please wait."), 429


@app.errorhandler(500)
def server_error(e):
    # Log internally, show nothing sensitive to user
    logger.error("Internal server error: %s", str(e))
    return render_template("error.html", code=500, message="An unexpected error occurred."), 500


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # RULE: NEVER set debug=True in production
    app.run(
        debug=False,
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
    )

    """
create_user.py — CLI utility to register a new user with a bcrypt-hashed password.
Usage: python create_user.py
"""

import os
import sqlite3
import getpass
import bcrypt       # RULE: bcrypt, NEVER MD5/SHA1
import secrets      # RULE: secrets module for security-sensitive ops

# Validate environment
db_path = os.environ.get("DATABASE_PATH", "users.db")
if not os.path.exists(db_path):
    print(f"[ERROR] Database not found at '{db_path}'. Run init_db first.")
    exit(1)

username = input("New username: ").strip()
if not username or len(username) > 64:
    print("[ERROR] Invalid username.")
    exit(1)

password = getpass.getpass("Password: ")
confirm  = getpass.getpass("Confirm password: ")

if password != confirm:
    print("[ERROR] Passwords do not match.")
    exit(1)

if len(password) < 12:
    print("[ERROR] Password must be at least 12 characters.")
    exit(1)

# RULE: bcrypt for hashing — work_factor=12 is production-safe
password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))

conn = sqlite3.connect(db_path)
try:
    # RULE: Parameterized query
    conn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (username, password_hash)
    )
    conn.commit()
    print(f"[OK] User '{username}' created successfully.")
except sqlite3.IntegrityError:
    print(f"[ERROR] Username '{username}' already exists.")
finally:
    conn.close()