from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # In production, use a fixed secret key

DATABASE = 'users.db'

# ─── Database helpers ────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                email    TEXT
            )
        ''')
        db.commit()

        # Seed a demo user if none exist
        if not db.execute('SELECT 1 FROM users').fetchone():
            db.execute(
                'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                ('demo', generate_password_hash('demo1234'), 'demo@example.com')
            )
            db.commit()

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return redirect(url_for('dashboard') if 'user' in session else url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        with get_db() as db:
            user = db.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

        if user and check_password_hash(user['password'], password):
            session['user'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'

    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        email    = request.form.get('email', '').strip()

        if len(username) < 3:
            error = 'Username must be at least 3 characters.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            try:
                with get_db() as db:
                    db.execute(
                        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                        (username, generate_password_hash(password), email)
                    )
                    db.commit()
                flash('Account created! Please log in.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already taken.'

    return render_template('register.html', error=error)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['user'])

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == '__main__':
    init_db()
    app.run(debug=False)