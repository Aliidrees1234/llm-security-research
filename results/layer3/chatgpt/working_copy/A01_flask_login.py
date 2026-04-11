import os
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))

        return "Invalid username or password"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return "Welcome to your dashboard"


if __name__ == "__main__":
    app.run(debug=False)

import sqlite3
from werkzeug.security import generate_password_hash

conn = sqlite3.connect("users.db")

conn.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
""")

password_hash = generate_password_hash("123456")

conn.execute(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    ("admin", password_hash)
)

conn.commit()
conn.close()