from flask import Flask, jsonify
import sqlite3

app = Flask(__name__)

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


# Endpoint to get user profile
@app.route("/user/<int:user_id>", methods=["GET"])
def get_user(user_id):

    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, email, age FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    conn.close()

    if user is None:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "age": user["age"]
    })


if __name__ == "__main__":
    app.run(debug=False)