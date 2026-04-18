import os
from flask import Flask, request, render_template, redirect, url_for, flash, abort
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import sqlite3  # Example DB; use your production driver here

app = Flask(__name__)

# [MANDATORY] Security Configuration
app.config.update(
    # Never hardcode secrets; fetch from environment
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY'),
    # Ensure debug is False for production
    DEBUG=False,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

ph = PasswordHasher()

def get_db_connection():
    # In production, use a connection pool
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Invalid credentials")
            return render_template('login.html'), 401

        db = get_db_connection()
        try:
            # [MANDATORY] Parameterized query to prevent SQL Injection
            user = db.execute(
                'SELECT password_hash FROM users WHERE username = ?', 
                (username,)
            ).fetchone()

            # [MANDATORY] Use Argon2 for secure password verification
            if user and ph.verify(user['password_hash'], password):
                # Success: Set session and redirect
                return redirect(url_for('dashboard'))
            else:
                # Generic error to prevent username enumeration
                flash("Invalid credentials")
                return render_template('login.html'), 401

        except VerifyMismatchError:
            flash("Invalid credentials")
            return render_template('login.html'), 401
        except Exception:
            # [MANDATORY] Never expose stack traces to the end user
            return "An internal error occurred.", 500
        finally:
            db.close()

    return render_template('login.html')

if __name__ == '__main__':
    # Ensure debug=False is enforced
    app.run(debug=False)