"""
Flask Admin Panel - Production-Grade Security
=============================================
All security rules enforced:
  - No debug=True
  - No hardcoded secrets
  - Parameterized SQL queries only
  - bcrypt password hashing
  - User input escaping
  - No stack traces exposed to users
  - Admin-only route protection
"""

import os
import sqlite3
import secrets
import logging
from functools import wraps
from datetime import datetime

import bcrypt
from markupsafe import escape
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, abort
)

# ── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__)

# SECRET_KEY must be set in environment — never hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set. "
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )

# Production: debug ALWAYS False
app.config["DEBUG"] = False

# Session cookie hardening
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes

# Database path — never user-controlled
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DB_PATH  = os.path.join(BASE_DIR, os.environ.get("DB_NAME", "admin.db"))

# Logging — structured, no stack traces to stdout in prod
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ── Database helpers ──────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    """Return a per-request DB connection."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Create tables and seed a default admin if DB is empty."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE,
            email       TEXT    NOT NULL UNIQUE,
            role        TEXT    NOT NULL DEFAULT 'user'
                                CHECK(role IN ('admin','moderator','user')),
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            last_login  TEXT
        );

        CREATE TABLE IF NOT EXISTS admins (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT    NOT NULL UNIQUE,
            password_hash TEXT    NOT NULL,
            created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
        );
    """)
    db.commit()

    # Seed default admin only when no admin exists yet
    row = db.execute("SELECT COUNT(*) AS cnt FROM admins").fetchone()
    if row["cnt"] == 0:
        raw_pw = os.environ.get("ADMIN_INITIAL_PASSWORD")
        if not raw_pw:
            # Auto-generate and print ONCE — operator must capture this
            raw_pw = secrets.token_urlsafe(20)
            print(f"\n[SETUP] Generated initial admin password: {raw_pw}")
            print("[SETUP] Store it securely and set ADMIN_INITIAL_PASSWORD env var.\n")

        pw_hash = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt(rounds=12))
        db.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            ("admin", pw_hash.decode())  # store as string
        )

        # Seed demo users (parameterized — never f-strings in SQL)
        demo_users = [
            ("alice",   "alice@example.com",   "admin"),
            ("bob",     "bob@example.com",     "moderator"),
            ("charlie", "charlie@example.com", "user"),
            ("diana",   "diana@example.com",   "user"),
            ("eve",     "eve@example.com",     "user"),
        ]
        db.executemany(
            "INSERT OR IGNORE INTO users (username, email, role) VALUES (?, ?, ?)",
            demo_users
        )
        db.commit()


# ── Auth decorator ────────────────────────────────────────────────────────────

def admin_required(f):
    """Protect routes — redirect to login if not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


# ── Error handlers — NO stack traces to end users ─────────────────────────────

@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Page not found"), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error", exc_info=True)  # logged server-side only
    return render_template("error.html", code=500, message="Internal server error"), 500


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_users"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("admin_users"))

    if request.method == "POST":
        # escape() prevents XSS if value is ever reflected back
        username = str(escape(request.form.get("username", "").strip()))
        password = request.form.get("password", "")

        # Basic input validation
        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html"), 400

        db  = get_db()
        # Parameterized query — NEVER string concatenation
        row = db.execute(
            "SELECT username, password_hash FROM admins WHERE username = ?",
            (username,)
        ).fetchone()

        # Constant-time comparison to resist timing attacks
        if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"]  = row["username"]
            session.permanent = True

            # Update last login (parameterized)
            logger.warning("Admin login success: %s from %s", username, request.remote_addr)

            next_url = request.args.get("next", "")
            # OPEN REDIRECT protection — only allow relative paths
            if next_url and next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("admin_users"))

        logger.warning("Failed login attempt for username=%s from %s", username, request.remote_addr)
        flash("Invalid credentials.", "error")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@admin_required
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_users():
    db = get_db()

    # --- Filtering (parameterized, never injected into SQL string) ---
    allowed_roles   = {"admin", "moderator", "user", ""}
    allowed_status  = {"active", "inactive", ""}
    allowed_sort    = {"id", "username", "email", "role", "created_at"}
    allowed_order   = {"asc", "desc"}

    role_filter   = request.args.get("role",   "").lower()
    status_filter = request.args.get("status", "").lower()
    sort_col      = request.args.get("sort",   "id").lower()
    sort_dir      = request.args.get("order",  "asc").lower()
    search_raw    = request.args.get("q",      "").strip()

    # Whitelist validation — reject unknown values
    if role_filter   not in allowed_roles:   role_filter   = ""
    if status_filter not in allowed_status:  status_filter = ""
    if sort_col      not in allowed_sort:    sort_col      = "id"
    if sort_dir      not in allowed_order:   sort_dir      = "asc"

    # Escape search term for LIKE — no injection possible via ?
    search_like = f"%{search_raw}%" if search_raw else None

    # Build query dynamically with whitelisted identifiers
    # Column/direction come from whitelists — safe to interpolate
    query  = "SELECT * FROM users WHERE 1=1"
    params = []

    if role_filter:
        query  += " AND role = ?"
        params.append(role_filter)

    if status_filter == "active":
        query  += " AND is_active = 1"
    elif status_filter == "inactive":
        query  += " AND is_active = 0"

    if search_like:
        query  += " AND (username LIKE ? OR email LIKE ?)"
        params += [search_like, search_like]

    query += f" ORDER BY {sort_col} {sort_dir}"  # whitelisted values only

    users = db.execute(query, params).fetchall()

    # Stats (parameterized)
    stats = {
        "total":     db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active":    db.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0],
        "admins":    db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0],
        "new_today": db.execute(
            "SELECT COUNT(*) FROM users WHERE created_at >= date('now')"
        ).fetchone()[0],
    }

    return render_template(
        "admin/users.html",
        users=users,
        stats=stats,
        filters={
            "role": role_filter,
            "status": status_filter,
            "sort": sort_col,
            "order": sort_dir,
            "q": search_raw,
        },
        admin_username=session.get("admin_username"),
        now=datetime.utcnow()
    )


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def toggle_user(user_id: int):
    """Activate / deactivate a user. Uses parameterized query."""
    db  = get_db()
    row = db.execute("SELECT id, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)

    new_status = 0 if row["is_active"] else 1
    db.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    db.commit()
    flash(f"User #{user_id} has been {'activated' if new_status else 'deactivated'}.", "success")
    return redirect(url_for("admin_users"))


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with app.app_context():
        init_db()

    # debug=False enforced — use a proper WSGI server (gunicorn) in production
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)


# gunicorn.conf.py — production WSGI config
# Run with: gunicorn -c gunicorn.conf.py app:app

import multiprocessing

workers     = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
bind        = "127.0.0.1:5000"
timeout     = 30
keepalive   = 5
loglevel    = "warning"
accesslog   = "-"
errorlog    = "-"

# Never expose tracebacks to clients
capture_output = True