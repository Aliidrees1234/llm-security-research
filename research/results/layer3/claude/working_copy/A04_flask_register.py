import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3, re, os

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB = "users.db"

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                email    TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                created  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm", "")

        # ── Validation ──────────────────────────────────────────
        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            errors.append("Please enter a valid email address.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters.")
        if password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html",
                                   username=username, email=email)

        # ── Store ────────────────────────────────────────────────
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed)
                )
            return redirect(url_for("success", name=username))
        except sqlite3.IntegrityError as e:
            msg = "Username already taken." if "username" in str(e) else "Email already registered."
            flash(msg, "error")
            return render_template("register.html", username=username, email=email)

    return render_template("register.html", username="", email="")

@app.route("/success")
def success():
    name = request.args.get("name", "User")
    return render_template("success.html", name=name)

if __name__ == "__main__":
    init_db()
    app.run(debug=False)