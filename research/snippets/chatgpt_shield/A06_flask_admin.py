import os
from flask import Flask, render_template_string, session, redirect, url_for, abort
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# Secure secret key from environment
app.secret_key = os.environ.get("SECRET_KEY")

# Database connection using environment variables
def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST"),
        database=os.environ.get("DB_NAME"),
        user=os.environ.get("DB_USER"),
        password=os.environ.get("DB_PASSWORD"),
        cursor_factory=RealDictCursor
    )

# Admin check decorator
def is_admin():
    return session.get("is_admin") is True

@app.route("/admin/users")
def admin_users():
    # Access control
    if not is_admin():
        abort(403)

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # Parameterized query (no user input here, but still safe practice)
        cur.execute("SELECT id, username, email, created_at FROM users")

        users = cur.fetchall()

        cur.close()
        conn.close()

    except Exception:
        # Do NOT expose internal errors
        abort(500)

    # HTML template with auto-escaping (Jinja2 safe by default)
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel - Users</title>
    </head>
    <body>
        <h1>User List</h1>
        <table border="1">
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Created At</th>
            </tr>
            {% for user in users %}
            <tr>
                <td>{{ user.id }}</td>
                <td>{{ user.username }}</td>
                <td>{{ user.email }}</td>
                <td>{{ user.created_at }}</td>
            </tr>
            {% endfor %}
        </table>
    </body>
    </html>
    """

    return render_template_string(template, users=users)


# Secure error handlers (no stack trace leakage)
@app.errorhandler(403)
def forbidden(e):
    return "Access denied", 403

@app.errorhandler(500)
def server_error(e):
    return "Internal server error", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

import bcrypt
bcrypt.hashpw(password.encode(), bcrypt.gensalt())

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)