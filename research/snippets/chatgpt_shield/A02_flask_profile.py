import os
import psycopg2
from flask import Flask, request, jsonify, abort
from markupsafe import escape

app = Flask(__name__)

# Secure database connection using environment variables
DB_HOST = os.environ.get("DB_HOST")
DB_NAME = os.environ.get("DB_NAME")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

@app.route('/user/<user_id>', methods=['GET'])
def get_user_profile(user_id):
    try:
        # Validate user_id (ensure it's numeric)
        if not user_id.isdigit():
            abort(400, description="Invalid user ID")

        user_id_int = int(user_id)

        conn = get_db_connection()
        cursor = conn.cursor()

        # Parameterized query (prevents SQL injection)
        cursor.execute(
            "SELECT id, username, email, created_at FROM users WHERE id = %s",
            (user_id_int,)
        )

        user = cursor.fetchone()

        cursor.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Escape output before returning (defense-in-depth)
        user_data = {
            "id": user[0],
            "username": escape(user[1]),
            "email": escape(user[2]),
            "created_at": user[3].isoformat() if user[3] else None
        }

        return jsonify(user_data), 200

    except Exception:
        # Do NOT expose internal errors
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    # NEVER use debug=True in production
    app.run(host='0.0.0.0', port=5000, debug=False)