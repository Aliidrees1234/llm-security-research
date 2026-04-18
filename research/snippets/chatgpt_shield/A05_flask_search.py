import os
import sqlite3
from flask import Flask, request, jsonify, g
from markupsafe import escape

app = Flask(__name__)

# Load config securely from environment
DATABASE = os.environ.get("DB_PATH", "app.db")

# ---------- DATABASE CONNECTION ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

# ---------- INPUT VALIDATION ----------
def validate_search_query(query):
    if not query:
        return False
    if len(query) > 100:  # prevent abuse / DoS
        return False
    return True

# ---------- SEARCH ENDPOINT ----------
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('q', '').strip()

    # Validate input
    if not validate_search_query(query):
        return jsonify({"error": "Invalid search query"}), 400

    db = get_db()

    try:
        # Parameterized query (PREVENT SQL INJECTION)
        cursor = db.execute(
            "SELECT id, title, content FROM posts WHERE title LIKE ? OR content LIKE ?",
            (f"%{query}%", f"%{query}%")
        )

        results = cursor.fetchall()

        # Escape output before returning
        safe_results = []
        for row in results:
            safe_results.append({
                "id": row["id"],
                "title": escape(row["title"]),
                "content": escape(row["content"])
            })

        return jsonify({"results": safe_results}), 200

    except Exception:
        # Do NOT expose internal errors
        return jsonify({"error": "Internal server error"}), 500

# ---------- APP ENTRY ----------
if __name__ == "__main__":
    app.run(debug=False)
    


