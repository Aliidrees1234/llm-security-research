import os
"""
Flask Password Reset via Email Token
=====================================
Routes:
  POST /auth/forgot-password   → sends reset email
  GET  /auth/reset-password    → validates token (UI)
  POST /auth/reset-password    → sets new password
"""

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from datetime import datetime
from utils.token import generate_reset_token, verify_reset_token
from utils.email import send_reset_email
from utils.security import hash_password, check_password

app = Flask(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
app.config.update(
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),          # used for token signing
    SQLALCHEMY_DATABASE_URI="sqlite:///users.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,

    # Flask-Mail (swap for your real SMTP credentials)
    MAIL_SERVER="smtp.gmail.com",
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME="your-email@gmail.com",          # ← set via env var in prod
    MAIL_PASSWORD=os.environ.get('MAIL_PASSWORD'),             # ← set via env var in prod
    MAIL_DEFAULT_SENDER="your-email@gmail.com",
)

db   = SQLAlchemy(app)
mail = Mail(app)


# ── Model ──────────────────────────────────────────────────────────────────────
class User(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    """
    Accepts JSON: { "email": "user@example.com" }
    Always returns 200 to prevent user enumeration.
    """
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return jsonify({"error": "Email is required."}), 400

    user = User.query.filter_by(email=email).first()

    # Even if user doesn't exist we respond the same way (security best practice)
    if user:
        token    = generate_reset_token(app, email)
        reset_url = url_for("reset_password", token=token, _external=True)
        send_reset_email(mail, email, reset_url)

    return jsonify({
        "message": "If that email is registered you will receive a reset link shortly."
    }), 200


@app.route("/auth/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token") or (request.get_json(silent=True) or {}).get("token")

    # ── GET: show the reset form (or a JSON response for APIs) ──────────────
    if request.method == "GET":
        email = verify_reset_token(app, token)
        if not email:
            return render_template("invalid_token.html"), 400
        return render_template("reset_password.html", token=token)

    # ── POST: apply the new password ─────────────────────────────────────────
    data         = request.get_json(silent=True) or {}
    token        = token or data.get("token")
    new_password = data.get("password", "").strip()

    # 1. Validate token
    email = verify_reset_token(app, token)
    if not email:
        return jsonify({"error": "Reset link is invalid or has expired."}), 400

    # 2. Validate password strength
    error = _validate_password(new_password)
    if error:
        return jsonify({"error": error}), 422

    # 3. Find user and update password
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    user.password_hash = hash_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password updated successfully. You can now log in."}), 200


# ── Demo routes (seed & login) ─────────────────────────────────────────────────

@app.route("/demo/seed")
def seed():
    """Creates a demo user for testing."""
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email="demo@example.com").first():
            db.session.add(User(
                email="demo@example.com",
                password_hash=hash_password("OldPassword1!")
            ))
            db.session.commit()
    return jsonify({"message": "Demo user created: demo@example.com"}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    """Minimal login endpoint to verify the new password works."""
    data     = request.get_json(silent=True) or {}
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = User.query.filter_by(email=email).first()
    if user and check_password(password, user.password_hash):
        return jsonify({"message": f"Welcome, {user.email}!"}), 200
    return jsonify({"error": "Invalid credentials."}), 401


# ── Helpers ────────────────────────────────────────────────────────────────────

def _validate_password(password: str) -> str | None:
    """Returns an error string or None if valid."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    return None


# ── Entry point ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False, port=5000)