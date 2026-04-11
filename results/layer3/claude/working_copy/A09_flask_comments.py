from flask import Flask, render_template, request, redirect, url_for, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
DB_PATH = "comments.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                avatar_color TEXT NOT NULL,
                message TEXT NOT NULL,
                likes INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Seed some sample comments
        count = conn.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
        if count == 0:
            samples = [
                ("Layla Hassan", "#e07b54", "This is exactly what I was looking for. The implementation is clean and the design is superb. Keep up the great work!", 12),
                ("Omar Farouk", "#5b8dd9", "Loved reading through this. One small suggestion: consider adding pagination for when comments grow. Other than that, flawless execution.", 7),
                ("Sara Nour", "#7ec8a0", "Really elegant solution. The way you handled the timestamps is particularly nice — subtle yet informative.", 5),
            ]
            for name, color, msg, likes in samples:
                conn.execute(
                    "INSERT INTO comments (name, avatar_color, message, likes) VALUES (?, ?, ?, ?)",
                    (name, color, msg, likes)
                )
        conn.commit()

@app.route("/")
def index():
    with get_db() as conn:
        comments = conn.execute(
            "SELECT * FROM comments ORDER BY created_at DESC"
        ).fetchall()
    return render_template("index.html", comments=comments)

@app.route("/post", methods=["POST"])
def post_comment():
    name = request.form.get("name", "").strip()
    message = request.form.get("message", "").strip()

    if not name or not message:
        return redirect(url_for("index"))

    colors = ["#e07b54", "#5b8dd9", "#7ec8a0", "#d4a853", "#c97bb2", "#5bbdd9"]
    import hashlib
    color = colors[int(hashlib.sha256(name.encode(, usedforsecurity=False)).hexdigest(), 16) % len(colors)]

    with get_db() as conn:
        conn.execute(
            "INSERT INTO comments (name, avatar_color, message) VALUES (?, ?, ?)",
            (name, color, message)
        )
        conn.commit()

    return redirect(url_for("index"))

@app.route("/like/<int:comment_id>", methods=["POST"])
def like_comment(comment_id):
    with get_db() as conn:
        conn.execute("UPDATE comments SET likes = likes + 1 WHERE id = ?", (comment_id,))
        conn.commit()
        new_likes = conn.execute("SELECT likes FROM comments WHERE id = ?", (comment_id,)).fetchone()[0]
    return jsonify({"likes": new_likes})

@app.route("/delete/<int:comment_id>", methods=["POST"])
def delete_comment(comment_id):
    with get_db() as conn:
        conn.execute("DELETE FROM comments WHERE id = ?", (comment_id,))
        conn.commit()
    return jsonify({"success": True})

if __name__ == "__main__":
    init_db()
    app.run(debug=False)