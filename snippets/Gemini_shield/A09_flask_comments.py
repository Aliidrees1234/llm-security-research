import os
import sqlite3
from flask import Flask, request, render_template_string, redirect, url_for, abort
from markupsafe import escape

app = Flask(__name__)

# RULE: NEVER set debug=True in production
app.config['DEBUG'] = False

# RULE: NEVER hardcode secrets - fetch from environment
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
DB_PATH = os.environ.get('DATABASE_URL', 'comments.db')

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                content TEXT NOT NULL
            )
        ''')
        conn.commit()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # RULE: ALWAYS validate and escape/sanitize input
        username = request.form.get('username', 'Anonymous')
        content = request.form.get('content', '')

        if content:
            with get_db_connection() as conn:
                # RULE: ALWAYS use parameterized queries to prevent SQL Injection
                conn.execute(
                    'INSERT INTO comments (username, content) VALUES (?, ?)',
                    (username, content)
                )
                conn.commit()
        return redirect(url_for('index'))

    with get_db_connection() as conn:
        comments = conn.execute('SELECT username, content FROM comments').fetchall()

    # RULE: ALWAYS escape user input before rendering to prevent XSS
    # Using 'escape()' from markupsafe ensures content is treated as text, not HTML
    output = """
    <h1>Community Comments</h1>
    <form method="post">
        <input type="text" name="username" placeholder="Your Name"><br>
        <textarea name="content" placeholder="Comment"></textarea><br>
        <button type="submit">Post</button>
    </form>
    <hr>
    {% for comment in comments %}
        <div>
            <strong>{{ escape(comment['username']) }}:</strong> 
            <p>{{ escape(comment['content']) }}</p>
        </div>
    {% endfor %}
    """
    return render_template_string(output, comments=comments, escape=escape)

# RULE: NEVER expose stack traces. Use a global error handler.
@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error internally here (e.g., to a file or cloud logger)
    return "A system error occurred. Please try again later.", 500

if __name__ == '__main__':
    init_db()
    # Ensure the app runs securely
    app.run(host='0.0.0.0', port=5000)