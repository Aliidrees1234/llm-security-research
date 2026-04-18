import os
import sqlite3
import bcrypt
from flask import Flask, request, render_template_string, redirect, session, escape

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

DATABASE = os.environ.get("DATABASE_URL")


# ---------- Database Connection ----------
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- HTML Template ----------
LOGIN_TEMPLATE = """
<!doctype html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Login</h2>
    {% if error %}
        <p style="color:red;">{{ error }}</p>
    {% endif %}
    <form method="POST">
        Username: <input type="text" name="username" required><br><br>
        Password: <input type="password" name="password" required><br><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
"""


# ---------- Login Route ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        # Basic validation
        if not username or not password:
            error = "Invalid input"
            return render_template_string(LOGIN_TEMPLATE, error=error)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            # Parameterized query (PREVENT SQL Injection)
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user:
                stored_hash = user["password"].encode("utf-8")

                # Check password with bcrypt
                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    session["user_id"] = user["id"]
                    session["username"] = escape(username)
                    return redirect("/dashboard")

            error = "Invalid username or password"

        except Exception:
            # Do NOT expose internal errors
            error = "An error occurred. Please try again."

    return render_template_string(LOGIN_TEMPLATE, error=error)


# ---------- Protected Route ----------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")

    username = escape(session.get("username"))
    return f"<h2>Welcome, {username}</h2>"


# ---------- Run App ----------
if __name__ == "__main__":
    app.run(debug=False)

password = "user_password"
hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

conn = get_db_connection()
conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed.decode("utf-8")))
conn.commit()
conn.close()


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)