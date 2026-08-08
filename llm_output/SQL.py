import os
import re
import sqlite3
from flask import Flask, request, jsonify, session
import werkzeug.security

app = Flask(__name__)

# [SCP-02] Load secret key from environment variable; raise error if missing
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("CRITICAL: FLASK_SECRET_KEY environment variable is not set.")
app.secret_key = SECRET_KEY

# Security & DB Configuration
DB_PATH = os.environ.get('DATABASE_PATH', 'app.db')
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_.]{3,32}$')  # Alphanumeric, dots, underscores (3-32 chars)

def get_db_connection():
    """Establish a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['POST'])
def login():
    # Enforce JSON payload
    if not request.is_json:
        return jsonify({'error': 'Invalid content type. Expected application/json.'}), 400

    data = request.get_json()

    # [SCP-08] Safely extract and validate required fields
    raw_username = data.get('username')
    raw_password = data.get('password')

    if not isinstance(raw_username, str) or not isinstance(raw_password, str):
        return jsonify({'error': 'Invalid request format.'}), 400

    username = raw_username.strip()
    password = raw_password

    # Input constraints: Whitelist characters, enforce length limits
    if not USERNAME_REGEX.match(username):
        return jsonify({'error': 'Invalid credentials.'}), 400  # Generic error message

    if len(password) < 8 or len(password) > 128:
        return jsonify({'error': 'Invalid credentials.'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # [SCP-04] Parameterized query to prevent SQL Injection (CWE-89)
        cursor.execute(
            'SELECT id, username, password_hash FROM users WHERE username = ?', 
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        # [SCP-08] Constant-time password verification using Werkzeug (PBKDF2/Argon2)
        if user is None or not werkzeug.security.check_password_hash(user['password_hash'], password):
            # Generic error response prevents username enumeration
            return jsonify({'error': 'Invalid credentials.'}), 401

        # Prevent Session Fixation: Regenerate session state upon successful login
        session.clear()
        session['user_id'] = user['id']
        session['username'] = user['username']

        return jsonify({'message': 'Login successful.'}), 200

    except sqlite3.Error:
        # [SCP-08] Log internal exception securely on server side; return generic error to user (CWE-209)
        app.logger.error("Database error during user login attempt.")
        return jsonify({'error': 'An internal error occurred.'}), 500
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({'error': 'An internal error occurred.'}), 500

if __name__ == '__main__':
    # [SCP-01] Ensure debug mode is strictly disabled and bound locally
    port = int(os.environ.get('PORT', 5000))
    app.run(debug=False, host='127.0.0.1', port=port)