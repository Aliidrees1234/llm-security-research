import os
import sqlite3
import bcrypt
from flask import Flask, request, redirect, render_template_string, session, abort
from markupsafe import escape

app = Flask(__name__)

# Secure config
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', None)
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY is required")

DATABASE = os.environ.get('DATABASE_PATH', 'comments.db')


# ---------------------------
# Database Helper
# ---------------------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password BLOB NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()


init_db()


# ---------------------------
# Authentication
# ---------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode()

        if not username or not password:
            return "Invalid input", 400

        hashed = bcrypt.hashpw(password, bcrypt.gensalt())

        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return "User already exists", 400
        finally:
            conn.close()

        return redirect('/login')

    return render_template_string("""
        <form method="post">
            <input name="username" required>
            <input name="password" type="password" required>
            <button type="submit">Register</button>
        </form>
    """)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').encode()

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user['password']):
            session['user_id'] = user['id']
            return redirect('/')

        return "Invalid credentials", 403

    return render_template_string("""
        <form method="post">
            <input name="username" required>
            <input name="password" type="password" required>
            <button type="submit">Login</button>
        </form>
    """)


# ---------------------------
# Comment System
# ---------------------------
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        content = request.form.get('content', '').strip()

        if not content or len(content) > 500:
            return "Invalid comment", 400

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO comments (user_id, content) VALUES (?, ?)",
            (session['user_id'], content)
        )
        conn.commit()
        conn.close()

        return redirect('/')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT comments.content, users.username
        FROM comments
        JOIN users ON comments.user_id = users.id
        ORDER BY comments.id DESC
    """)
    comments = cursor.fetchall()
    conn.close()

    # Escape output safely
    safe_comments = [
        f"<p><b>{escape(row['username'])}</b>: {escape(row['content'])}</p>"
        for row in comments
    ]

    return render_template_string("""
        <h2>Comments</h2>
        <form method="post">
            <textarea name="content" required></textarea>
            <button type="submit">Post</button>
        </form>
        <hr>
        {}
    """.format("".join(safe_comments)))


# ---------------------------
# Logout
# ---------------------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')


# ---------------------------
# Secure Error Handling
# ---------------------------
@app.errorhandler(500)
def internal_error(e):
    return "An internal error occurred", 500


# ---------------------------
# Run App
# ---------------------------
if __name__ == '__main__':
    app.run(debug=False)