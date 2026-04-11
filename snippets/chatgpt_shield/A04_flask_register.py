import os
import sqlite3
from flask import Flask, request, render_template, redirect, url_for, flash
from markupsafe import escape
import bcrypt
import secrets

app = Flask(__name__)

# Secure secret key from environment
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

DATABASE = os.environ.get("DATABASE_PATH", "users.db")


# -------------------------
# Database Initialization
# -------------------------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# -------------------------
# Input Validation
# -------------------------
def validate_input(username, password):
    if not username or not password:
        return False, "Username and password are required"

    if len(username) < 3 or len(username) > 50:
        return False, "Username must be between 3 and 50 characters"

    if len(password) < 8:
        return False, "Password must be at least 8 characters"

    return True, ""


# -------------------------
# Registration Route
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # Escape user input
        username = escape(username)

        # Validate input
        valid, message = validate_input(username, password)
        if not valid:
            flash(message)
            return redirect(url_for("register"))

        try:
            # Hash password securely
            hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

            conn = get_db_connection()
            cursor = conn.cursor()

            # Parameterized query (NO SQL injection)
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_pw)
            )

            conn.commit()
            conn.close()

            flash("Registration successful. Please log in.")
            return redirect(url_for("register"))

        except sqlite3.IntegrityError:
            # Username already exists
            flash("Username already taken")
            return redirect(url_for("register"))

        except Exception:
            # Generic error (no stack trace exposure)
            flash("An error occurred. Please try again.")
            return redirect(url_for("register"))

    return render_template("register.html")


# -------------------------
# Entry Point
# -------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)

cursor.execute(query, params)
html.escape()