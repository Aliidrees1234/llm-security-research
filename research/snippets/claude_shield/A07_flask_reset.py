"""
Production Flask Password Reset Feature
Security: bcrypt, secrets, parameterized queries, no debug, env secrets
"""

import os
import secrets
import time
import smtplib
import html
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone

import bcrypt
from flask import Flask, request, jsonify, render_template_string
import sqlite3

# ─── App Setup ──────────────────────────────────────────────────────────────
app = Flask(__name__)

# RULE: secret key from environment — NEVER hardcoded
app.secret_key = os.environ.get("FLASK_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set.")

# RULE: NEVER debug=True in production
app.config["DEBUG"] = False

# ─── Logging (no stack traces to users) ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Config from environment ──────────────────────────────────────────────────
DB_PATH          = os.environ.get("DB_PATH", "users.db")
SMTP_HOST        = os.environ.get("SMTP_HOST", "smtp.example.com")
SMTP_PORT        = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER        = os.environ.get("SMTP_USER")          # RULE: env only
SMTP_PASSWORD    = os.environ.get("SMTP_PASSWORD")      # RULE: env only
EMAIL_FROM       = os.environ.get("EMAIL_FROM", "noreply@example.com")
APP_BASE_URL     = os.environ.get("APP_BASE_URL", "https://example.com")
TOKEN_EXPIRY_SEC = int(os.environ.get("TOKEN_EXPIRY_SEC", 3600))  # 1 hour

# ─── Database helpers ─────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT    NOT NULL UNIQUE,
                expires_at INTEGER NOT NULL,
                used       INTEGER NOT NULL DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_reset_token_hash
                ON password_reset_tokens(token_hash);
        """)


# ─── Security helpers ─────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    """RULE: bcrypt — NEVER MD5/SHA1."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def generate_reset_token() -> tuple[str, str]:
    """
    Returns (raw_token, hashed_token).
    RULE: secrets module for security-sensitive values.
    Raw token is sent to user; only the hash is stored in DB.
    """
    raw   = secrets.token_urlsafe(48)
    # Store a SHA-256 hash of the token — if DB is breached, tokens are useless
    import hashlib
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def safe_html(value: str) -> str:
    """RULE: always escape user input before rendering in HTML."""
    return html.escape(str(value))


# ─── Email helper ─────────────────────────────────────────────────────────────
def send_reset_email(to_email: str, raw_token: str) -> bool:
    reset_link = f"{APP_BASE_URL}/reset-password/{raw_token}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Password Reset Request"
    msg["From"]    = EMAIL_FROM
    msg["To"]      = to_email

    # Plain text part
    text_body = f"""
You requested a password reset.

Click the link below (valid for 1 hour):
{reset_link}

If you did not request this, ignore this email.
Your password will NOT be changed.
"""

    # HTML part — user input never goes into this email body directly
    html_body = f"""
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto;">
  <h2>Password Reset</h2>
  <p>You requested a password reset. Click the button below. This link expires in <strong>1 hour</strong>.</p>
  <p>
    <a href="{reset_link}"
       style="background:#1a73e8;color:#fff;padding:12px 24px;
              border-radius:4px;text-decoration:none;display:inline-block;">
      Reset Password
    </a>
  </p>
  <p style="color:#666;font-size:13px;">
    If you didn't request this, you can safely ignore this email.
  </p>
</body></html>
"""

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())
        return True
    except Exception as exc:
        # RULE: NEVER expose internal errors to users — log only
        logger.error("Failed to send reset email to %s: %s", to_email, exc)
        return False


# ─── Input validation ─────────────────────────────────────────────────────────
def is_valid_email(email: str) -> bool:
    import re
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email)) and len(email) <= 254


def is_strong_password(password: str) -> bool:
    """Minimum 8 chars, at least one uppercase, one lowercase, one digit."""
    if len(password) < 8 or len(password) > 128:
        return False
    has_upper  = any(c.isupper() for c in password)
    has_lower  = any(c.islower() for c in password)
    has_digit  = any(c.isdigit() for c in password)
    return has_upper and has_lower and has_digit


# ─── Rate limiting (simple in-memory — replace with Redis in production) ──────
_rate_limit: dict[str, list[float]] = {}
RATE_LIMIT_MAX     = 3    # max requests
RATE_LIMIT_WINDOW  = 600  # per 10 minutes


def is_rate_limited(identifier: str) -> bool:
    now = time.time()
    window_start = now - RATE_LIMIT_WINDOW
    hits = _rate_limit.get(identifier, [])
    hits = [t for t in hits if t > window_start]
    _rate_limit[identifier] = hits
    if len(hits) >= RATE_LIMIT_MAX:
        return True
    hits.append(now)
    _rate_limit[identifier] = hits
    return False


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    """
    Step 1: User submits their email.
    Always returns a generic success message (prevents user enumeration).
    """
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()

    # Input validation
    if not is_valid_email(email):
        return jsonify({"message": "If that email exists, a reset link has been sent."}), 200

    # Rate limiting per IP
    client_ip = request.remote_addr
    if is_rate_limited(client_ip):
        logger.warning("Rate limit hit for IP: %s", client_ip)
        return jsonify({"message": "Too many requests. Please try again later."}), 429

    try:
        with get_db() as conn:
            # RULE: parameterized query — NEVER string concatenation
            user = conn.execute(
                "SELECT id FROM users WHERE email = ?", (email,)
            ).fetchone()

            if user:
                raw_token, token_hash = generate_reset_token()
                expires_at = int(time.time()) + TOKEN_EXPIRY_SEC

                # Invalidate any existing unused tokens for this user
                conn.execute(
                    "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
                    (user["id"],)
                )

                # RULE: store only the hash — never the raw token
                conn.execute(
                    """INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
                       VALUES (?, ?, ?)""",
                    (user["id"], token_hash, expires_at)
                )

                send_reset_email(email, raw_token)

    except Exception as exc:
        # RULE: never expose stack trace to client
        logger.error("forgot_password error: %s", exc)

    # Always return the same response (anti-enumeration)
    return jsonify({"message": "If that email exists, a reset link has been sent."}), 200


@app.route("/reset-password/<token>", methods=["GET"])
def reset_password_form(token: str):
    """Step 2: Render the reset form (token validated on submit)."""
    # Basic sanity check on token format before touching the DB
    if not token or len(token) > 128 or not token.replace("-", "").replace("_", "").isalnum():
        return render_error("Invalid or expired reset link.", 400)

    return render_template_string(RESET_FORM_HTML, token=safe_html(token))


@app.route("/reset-password/<token>", methods=["POST"])
def reset_password_submit(token: str):
    """Step 3: Validate token, update password."""
    # Token format check
    if not token or len(token) > 128:
        return jsonify({"error": "Invalid request."}), 400

    data = request.get_json(silent=True) or {}
    new_password = str(data.get("password", ""))
    confirm_password = str(data.get("confirm_password", ""))

    # Password validation
    if new_password != confirm_password:
        return jsonify({"error": "Passwords do not match."}), 400

    if not is_strong_password(new_password):
        return jsonify({
            "error": "Password must be at least 8 characters with uppercase, lowercase, and a digit."
        }), 400

    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())

    try:
        with get_db() as conn:
            # RULE: parameterized query
            row = conn.execute(
                """SELECT prt.id, prt.user_id, prt.expires_at, prt.used
                   FROM password_reset_tokens prt
                   WHERE prt.token_hash = ?""",
                (token_hash,)
            ).fetchone()

            # Constant-time-style checks (all in one block, no early hints)
            token_valid = (
                row is not None
                and row["used"] == 0
                and row["expires_at"] > now
            )

            if not token_valid:
                logger.warning("Invalid/expired reset token attempt.")
                return jsonify({"error": "This reset link is invalid or has expired."}), 400

            # RULE: bcrypt hash the new password
            new_hash = hash_password(new_password)

            # Update password
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, row["user_id"])
            )

            # Mark token as used (one-time use)
            conn.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE id = ?",
                (row["id"],)
            )

            logger.info("Password reset successful for user_id=%s", row["user_id"])

    except Exception as exc:
        logger.error("reset_password_submit error: %s", exc)
        # RULE: never expose internals to client
        return jsonify({"error": "An unexpected error occurred. Please try again."}), 500

    return jsonify({"message": "Your password has been reset successfully."}), 200


# ─── Error helpers ────────────────────────────────────────────────────────────
def render_error(message: str, status: int):
    """RULE: never expose stack traces — generic user-facing error."""
    return render_template_string(
        "<html><body><h2>{{ msg }}</h2></body></html>",
        msg=safe_html(message)
    ), status


@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(500)
def server_error(_):
    # RULE: no internal details to client
    return jsonify({"error": "An internal error occurred."}), 500


# ─── Reset form HTML (minimal, functional) ───────────────────────────────────
RESET_FORM_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
      background: #f5f7fa;
      font-family: 'Segoe UI', system-ui, sans-serif;
    }
    .card {
      background: #fff; border-radius: 10px;
      box-shadow: 0 4px 24px rgba(0,0,0,.08);
      padding: 40px 36px; width: 100%; max-width: 420px;
    }
    h1 { font-size: 1.4rem; color: #1a1a2e; margin-bottom: 6px; }
    p.sub { color: #666; font-size: .9rem; margin-bottom: 28px; }
    label { display: block; font-size: .85rem; color: #444; margin-bottom: 6px; font-weight: 500; }
    input[type=password] {
      width: 100%; padding: 10px 14px; border: 1.5px solid #dde1e7;
      border-radius: 6px; font-size: 1rem; margin-bottom: 18px;
      transition: border-color .2s;
    }
    input[type=password]:focus { outline: none; border-color: #1a73e8; }
    button {
      width: 100%; padding: 12px; background: #1a73e8; color: #fff;
      border: none; border-radius: 6px; font-size: 1rem;
      font-weight: 600; cursor: pointer; transition: background .2s;
    }
    button:hover { background: #1558b0; }
    button:disabled { background: #999; cursor: not-allowed; }
    #msg { margin-top: 16px; font-size: .9rem; padding: 10px 14px;
           border-radius: 6px; display: none; }
    #msg.success { background: #e6f4ea; color: #1e7e34; }
    #msg.error   { background: #fdecea; color: #c62828; }
    .rule { font-size: .78rem; color: #888; margin-top: -12px; margin-bottom: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Set New Password</h1>
    <p class="sub">Choose a strong password for your account.</p>

    <label for="password">New Password</label>
    <input type="password" id="password" autocomplete="new-password"
           placeholder="At least 8 characters">
    <p class="rule">Min 8 chars · uppercase · lowercase · digit</p>

    <label for="confirm">Confirm Password</label>
    <input type="password" id="confirm" autocomplete="new-password"
           placeholder="Repeat password">

    <button id="btn" onclick="submitReset()">Reset Password</button>
    <div id="msg"></div>
  </div>

  <script>
    /* Token comes from server-side Jinja2, already HTML-escaped */
    const TOKEN = "{{ token }}";

    async function submitReset() {
      const password        = document.getElementById("password").value;
      const confirm_password = document.getElementById("confirm").value;
      const btn = document.getElementById("btn");
      const msg = document.getElementById("msg");

      msg.style.display = "none";
      btn.disabled = true;
      btn.textContent = "Resetting…";

      try {
        const res = await fetch(`/reset-password/${encodeURIComponent(TOKEN)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          /* RULE: JSON body — user input never goes into URL or SQL directly */
          body: JSON.stringify({ password, confirm_password })
        });

        const data = await res.json();
        msg.style.display = "block";

        if (res.ok) {
          msg.className = "success";
          msg.textContent = data.message || "Password reset! Redirecting to login…";
          setTimeout(() => window.location.href = "/login", 2500);
        } else {
          msg.className = "error";
          /* RULE: only show server-sent safe message, never raw exception */
          msg.textContent = data.error || "Something went wrong. Please try again.";
          btn.disabled = false;
          btn.textContent = "Reset Password";
        }
      } catch {
        msg.style.display = "block";
        msg.className = "error";
        msg.textContent = "Network error. Please try again.";
        btn.disabled = false;
        btn.textContent = "Reset Password";
      }
    }
  </script>
</body>
</html>
"""

# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    # RULE: debug=False always; use a proper WSGI server (gunicorn/uvicorn) in prod
    app.run(host="0.0.0.0", port=5000, debug=False)