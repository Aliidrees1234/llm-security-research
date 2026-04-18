from flask import Flask, render_template, request, jsonify
from datetime import datetime, timedelta
import random

app = Flask(__name__)

# --- Mock user data ---
ROLES = ["Admin", "Editor", "Viewer", "Moderator"]
STATUSES = ["active", "inactive", "suspended"]

def make_users():
    names = [
        ("Liam Carter", "liam@example.com"),
        ("Sofia Reyes", "sofia@example.com"),
        ("Marcus Webb", "marcus@example.com"),
        ("Aisha Patel", "aisha@example.com"),
        ("Ethan Brooks", "ethan@example.com"),
        ("Nora Lindqvist", "nora@example.com"),
        ("James Okonkwo", "james@example.com"),
        ("Yuki Tanaka", "yuki@example.com"),
        ("Diego Morales", "diego@example.com"),
        ("Chloe Dupont", "chloe@example.com"),
        ("Ravi Sharma", "ravi@example.com"),
        ("Elena Volkov", "elena@example.com"),
    ]
    users = []
    for i, (name, email) in enumerate(names, start=1):
        joined = datetime.now() - timedelta(days=random.randint(  # nosec B311 — non-security display data only10, 900))
        last_seen = datetime.now() - timedelta(hours=random.randint(  # nosec B311 — non-security display data only1, 720))
        users.append({
            "id": i,
            "name": name,
            "email": email,
            "role": random.choice(  # nosec B311 — non-security display data onlyROLES),
            "status": random.choice(  # nosec B311 — non-security display data onlySTATUSES),
            "joined": joined.strftime("%b %d, %Y"),
            "last_seen": last_seen.strftime("%b %d, %Y · %H:%M"),
            "avatar_initials": "".join(p[0] for p in name.split()),
        })
    return users

USERS = make_users()

@app.route("/")
def index():
    stats = {
        "total": len(USERS),
        "active": sum(1 for u in USERS if u["status"] == "active"),
        "inactive": sum(1 for u in USERS if u["status"] == "inactive"),
        "suspended": sum(1 for u in USERS if u["status"] == "suspended"),
    }
    return render_template("index.html", users=USERS, stats=stats)

@app.route("/api/users")
def api_users():
    query = request.args.get("q", "").lower()
    role = request.args.get("role", "")
    status = request.args.get("status", "")

    filtered = USERS
    if query:
        filtered = [u for u in filtered if query in u["name"].lower() or query in u["email"].lower()]
    if role:
        filtered = [u for u in filtered if u["role"] == role]
    if status:
        filtered = [u for u in filtered if u["status"] == status]

    return jsonify(filtered)

if __name__ == "__main__":
    app.run(debug=False)