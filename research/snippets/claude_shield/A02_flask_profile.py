"""
Production-ready Flask endpoint: GET /api/users/<user_id>/profile
Security rules applied:
  - No debug=True
  - No hardcoded secrets (all via os.environ)
  - Parameterized SQL queries (no string concatenation)
  - Input validation on user_id
  - No stack traces exposed to clients
  - HTML-escaped output (via jsonify — no raw HTML rendering)
  - bcrypt for any password fields (excluded from profile response)
  - secrets module used where randomness is needed
"""

import os
import re
import logging
import sqlite3
from functools import wraps

import bcrypt                          # pip install bcrypt
from flask import Flask, jsonify, g, request, abort
from markupsafe import escape          # pip install markupsafe (bundled with Flask)

# ---------------------------------------------------------------------------
# App setup — NEVER debug=True in production
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")          # [RULE] no hardcoded secret
app.config["DATABASE_URL"] = os.environ.get("DATABASE_URL", "app.db")  # [RULE] env var
app.config["DEBUG"] = False                                             # [RULE] always False

if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set.")

# ---------------------------------------------------------------------------
# Logging — structured, no sensitive data, no stack traces to users
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Database helpers — parameterized queries only
# ---------------------------------------------------------------------------
def get_db() -> sqlite3.Connection:
    """Return a per-request SQLite connection (swap for psycopg2/SQLAlchemy in prod)."""
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE_URL"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row  # dict-like rows
    return g.db


@app.teardown_appcontext
def close_db(exception: Exception | None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def fetch_user_profile(user_id: int) -> dict | None:
    """
    Retrieve profile columns — NEVER the password hash.
    [RULE] Parameterized query: the ? placeholder prevents SQL injection.
    """
    db = get_db()
    cursor = db.execute(
        """
        SELECT id, username, email, full_name, bio, avatar_url, created_at
        FROM users
        WHERE id = ? AND is_active = 1
        """,
        (user_id,),                    # [RULE] tuple param — no string concat
    )
    row = cursor.fetchone()
    return dict(row) if row else None

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------
_USER_ID_RE = re.compile(r"^\d{1,18}$")   # positive integer, max 18 digits


def validate_user_id(raw: str) -> int:
    """
    Reject anything that isn't a plain positive integer.
    Returns the validated integer or raises ValueError.
    """
    if not _USER_ID_RE.match(raw):
        raise ValueError("Invalid user_id format.")
    value = int(raw)
    if value <= 0:
        raise ValueError("user_id must be a positive integer.")
    return value

# ---------------------------------------------------------------------------
# Auth decorator — simple Bearer-token check (replace with JWT in real app)
# ---------------------------------------------------------------------------
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Authentication required."}), 401

        token = auth_header[7:]
        expected = os.environ.get("API_BEARER_TOKEN")  # [RULE] never hardcoded

        if not expected:
            logger.error("API_BEARER_TOKEN env var not configured.")
            # [RULE] never expose internal config errors to clients
            return jsonify({"error": "Server configuration error."}), 500

        # [RULE] constant-time comparison prevents timing attacks
        import hmac
        if not hmac.compare_digest(token.encode(), expected.encode()):
            return jsonify({"error": "Invalid or expired token."}), 403

        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# Profile endpoint
# ---------------------------------------------------------------------------
@app.route("/api/users/<string:raw_user_id>/profile", methods=["GET"])
@require_auth
def get_user_profile(raw_user_id: str):
    """
    GET /api/users/<user_id>/profile
    Returns public profile fields for the given user.
    """
    # 1. Validate & sanitize input ─────────────────────────────────────────
    try:
        user_id = validate_user_id(raw_user_id)
    except ValueError:
        # [RULE] generic message — no internal detail leaked
        return jsonify({"error": "Invalid user ID."}), 400

    # 2. Fetch from DB with parameterized query ────────────────────────────
    try:
        profile = fetch_user_profile(user_id)
    except Exception:
        # [RULE] log internally but NEVER expose stack traces to client
        logger.exception("Database error while fetching profile for user_id=%s", user_id)
        return jsonify({"error": "An internal error occurred. Please try again later."}), 500

    if profile is None:
        return jsonify({"error": "User not found."}), 404

    # 3. Escape all string fields before returning ─────────────────────────
    # jsonify already produces JSON (not raw HTML), but we escape defensively
    # in case this data is ever embedded in a template downstream.
    # [RULE] escape user-supplied text fields
    safe_profile = {
        "id":         profile["id"],
        "username":   str(escape(profile["username"])),
        "email":      str(escape(profile["email"])),
        "full_name":  str(escape(profile["full_name"] or "")),
        "bio":        str(escape(profile["bio"] or "")),
        "avatar_url": str(escape(profile["avatar_url"] or "")),
        "created_at": str(profile["created_at"]),
    }

    return jsonify({"status": "success", "data": safe_profile}), 200

# ---------------------------------------------------------------------------
# Generic error handlers — no stack traces to clients
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Resource not found."}), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(500)
def internal_error(_e):
    logger.exception("Unhandled 500 error")
    # [RULE] never expose debug info / stack traces
    return jsonify({"error": "An internal server error occurred."}), 500

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # [RULE] debug=False enforced; bind only to localhost for local dev
    app.run(host="127.0.0.1", port=5000, debug=False)