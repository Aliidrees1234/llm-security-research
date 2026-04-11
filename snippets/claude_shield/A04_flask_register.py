"""
Secure Flask Registration Application
Production-ready with all security best practices enforced.
"""

import os
import re
import secrets
import sqlite3
import logging
from datetime import datetime
from functools import wraps

import bcrypt
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, g, abort
)
from markupsafe import escape

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)

# SECRET_KEY must be set in environment — never hardcoded
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or (_ for _ in ()).throw(
    RuntimeError("SECRET_KEY environment variable is not set.")
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("HTTPS", "false").lower() == "true"

DATABASE = os.environ.get("DATABASE_PATH", "users.db")

# ---------------------------------------------------------------------------
# Logging — structured, no sensitive data
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation Rules
# ---------------------------------------------------------------------------
USERNAME_RE  = re.compile(r"^[a-zA-Z0-9_]{3,30}$")
EMAIL_RE     = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
MIN_PASSWORD = 8
MAX_PASSWORD = 128


def validate_username(value: str) -> str | None:
    """Return error message or None if valid."""
    if not value:
        return "Username is required."
    if not USERNAME_RE.match(value):
        return "Username must be 3–30 characters: letters, digits, underscores only."
    return None


def validate_email(value: str) -> str | None:
    if not value:
        return "Email is required."
    if not EMAIL_RE.match(value):
        return "Please enter a valid email address."
    return None


def validate_password(value: str) -> str | None:
    if not value:
        return "Password is required."
    if len(value) < MIN_PASSWORD:
        return f"Password must be at least {MIN_PASSWORD} characters."
    if len(value) > MAX_PASSWORD:
        return "Password is too long."
    if not re.search(r"[A-Z]", value):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", value):
        return "Password must contain at least one digit."
    if not re.search(r"[^a-zA-Z0-9]", value):
        return "Password must contain at least one special character."
    return None


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    # Parameterized schema — no user input here, but follows same secure style
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            email         TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL
        )
    """)
    db.commit()


# ---------------------------------------------------------------------------
# CSRF helpers  (secrets module — NOT random)
# ---------------------------------------------------------------------------
def generate_csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not secrets.compare_digest(token, session.get("csrf_token", "")):
                logger.warning("CSRF validation failed for %s", request.remote_addr)
                abort(403)
        return f(*args, **kwargs)
    return decorated


app.jinja_env.globals["csrf_token"] = generate_csrf_token


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
@csrf_protect
def register():
    errors = {}
    form_data = {"username": "", "email": ""}   # never echo passwords

    if request.method == "POST":
        # --- Collect & escape raw inputs ---
        username = str(escape(request.form.get("username", "").strip()))
        email    = str(escape(request.form.get("email",    "").strip().lower()))
        password =         request.form.get("password",         "")
        confirm  =         request.form.get("confirm_password", "")

        form_data["username"] = username
        form_data["email"]    = email

        # --- Validate ---
        if err := validate_username(username):
            errors["username"] = err
        if err := validate_email(email):
            errors["email"] = err
        if err := validate_password(password):
            errors["password"] = err
        elif password != confirm:
            errors["confirm_password"] = "Passwords do not match."

        if not errors:
            db = get_db()

            # --- Uniqueness check — PARAMETERIZED query ---
            existing = db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email)
            ).fetchone()

            if existing:
                # Don't reveal *which* field is taken to prevent enumeration
                errors["general"] = "An account with those details already exists."
            else:
                # --- Hash with bcrypt (work factor 12) ---
                pw_hash = bcrypt.hashpw(
                    password.encode("utf-8"),
                    bcrypt.gensalt(rounds=12)
                ).decode("utf-8")

                # --- INSERT with parameterized query ---
                db.execute(
                    """INSERT INTO users (username, email, password_hash, created_at)
                       VALUES (?, ?, ?, ?)""",
                    (username, email, pw_hash, datetime.utcnow().isoformat())
                )
                db.commit()
                logger.info("New user registered: %s", username)

                # Rotate CSRF token after successful action
                session.pop("csrf_token", None)
                return redirect(url_for("success"))

    return render_template(
        "register.html",
        errors=errors,
        form_data=form_data,
    )


@app.route("/success")
def success():
    return render_template("success.html")


# ---------------------------------------------------------------------------
# Error handlers — NEVER expose stack traces
# ---------------------------------------------------------------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access denied."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error")   # log full trace server-side only
    return render_template("error.html", code=500, message="Something went wrong."), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        init_db()

    # debug=False — MANDATORY for production
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )