import os
import sqlite3
import secrets
import hashlib
import time
import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")

DATABASE = os.environ.get("DATABASE_PATH", "app.db")
RESET_TOKEN_EXPIRY_SECONDS = 900  # 15 minutes


def get_db():
    return sqlite3.connect(DATABASE)


# ---------------------------
# Utility Functions
# ---------------------------

def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def send_email(to_email, reset_link):
    # Replace with real email provider (SendGrid, SES, etc.)
    print(f"[EMAIL] To: {to_email}")
    print(f"Reset link: {reset_link}")


def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()
    return user


# ---------------------------
# Request Password Reset
# ---------------------------

@app.route("/request-password-reset", methods=["POST"])
def request_password_reset():
    email = request.json.get("email", "").strip()

    if not email:
        return jsonify({"message": "If the account exists, a reset link has been sent."})

    user = get_user_by_email(email)

    if user:
        user_id = user[0]

        # Generate secure token
        token = secrets.token_urlsafe(32)
        token_hash = hash_token(token)
        expires_at = int(time.time()) + RESET_TOKEN_EXPIRY_SECONDS

        conn = get_db()
        cursor = conn.cursor()

        # Delete old tokens
        cursor.execute("DELETE FROM password_resets WHERE user_id = ?", (user_id,))

        # Store hashed token
        cursor.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
            (user_id, token_hash, expires_at)
        )
        conn.commit()
        conn.close()

        reset_link = f"{os.environ.get('BASE_URL')}/reset-password?token={token}"

        send_email(email, reset_link)

    # Always same response (prevents enumeration)
    return jsonify({"message": "If the account exists, a reset link has been sent."})


# ---------------------------
# Reset Password
# ---------------------------

@app.route("/reset-password", methods=["POST"])
def reset_password():
    token = request.json.get("token", "")
    new_password = request.json.get("password", "")

    if not token or not new_password:
        return jsonify({"error": "Invalid request"}), 400

    if len(new_password) < 8:
        return jsonify({"error": "Password too short"}), 400

    token_hash = hash_token(token)
    current_time = int(time.time())

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?",
        (token_hash,)
    )
    record = cursor.fetchone()

    if not record:
        conn.close()
        return jsonify({"error": "Invalid or expired token"}), 400

    user_id, expires_at = record

    if current_time > expires_at:
        cursor.execute("DELETE FROM password_resets WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return jsonify({"error": "Token expired"}), 400

    # Hash new password
    password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())

    cursor.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash.decode(), user_id)
    )

    # Delete token after use (single-use)
    cursor.execute("DELETE FROM password_resets WHERE user_id = ?", (user_id,))

    conn.commit()
    conn.close()

    return jsonify({"message": "Password reset successful"})


# ---------------------------
# Production Entry
# ---------------------------

if __name__ == "__main__":
    app.run(debug=False)