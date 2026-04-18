import os
import sqlite3
from flask import Flask, request, jsonify, render_template_string, abort
from markupsafe import escape

app = Flask(__name__)

# RULE: NEVER set debug=True in production
app.config['DEBUG'] = False

# RULE: NEVER hardcode secret keys
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

def get_db_connection():
    # In production, use environment variables for DB credentials
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    """
    Fetches user profile safely using parameterized queries and 
    proper input escaping.
    """
    try:
        db = get_db_connection()
        
        # RULE: ALWAYS use parameterized queries to prevent SQL Injection
        query = "SELECT username, bio, email FROM users WHERE id = ?"
        user = db.execute(query, (user_id,)).fetchone()
        db.close()

        if user is None:
            return jsonify({"error": "User not found"}), 404

        # RULE: ALWAYS escape user input before rendering (prevents XSS)
        # Even if data comes from our DB, we treat it as untrusted.
        safe_username = escape(user['username'])
        safe_bio = escape(user['bio'])

        return jsonify({
            "username": safe_username,
            "bio": safe_bio,
            "email": user['email']  # JSON responses are generally safe from XSS, 
                                    # but escaping is good practice for HTML templates.
        }), 200

    except Exception as e:
        # RULE: NEVER expose stack traces or debug info to end users
        # Log the actual error internally for devs, show generic error to user
        app.logger.error(f"Database error: {e}") 
        abort(500)

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "An internal server error occurred"}), 500

if __name__ == '__main__':
    # Ensure the app runs with debug disabled
    app.run(debug=False)