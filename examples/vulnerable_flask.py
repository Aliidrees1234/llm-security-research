"""
SHIELD Examples — Vulnerable Flask App
=======================================
This file represents typical LLM-generated Flask code WITHOUT security guidelines.
It contains the same vulnerabilities found in the empirical study (March 2026).

DO NOT use this in production.
Run: shield fix ./examples --output ./examples/fixed --report examples/report.html
"""

import hashlib
import subprocess
from flask import Flask, request, jsonify, session
import sqlite3
import random

app = Flask(__name__)

# B105 — Hardcoded secret key (CWE-259)
app.secret_key = "super_secret_key_123"

def get_db():
    return sqlite3.connect("users.db")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    # CUSTOM_SQL_FSTRING — SQL injection via f-string (CWE-89)
    conn = get_db()
    user = conn.execute(
        f"SELECT * FROM users WHERE username = '{username}'"
    ).fetchone()
    conn.close()

    if user:
        session["user"] = username
        return jsonify({"status": "ok"})
    return jsonify({"status": "fail"})

@app.route("/hash")
def weak_hash():
    data = request.args.get("data", "")
    # B324 — Weak hash (CWE-327)
    result = hashlib.md5(data.encode())
    return jsonify({"hash": result.hexdigest()})

@app.route("/run")
def run_command():
    cmd = request.args.get("cmd", "ls")
    # B602 — shell=True RCE (CWE-78)
    result = subprocess.check_output(cmd, shell=True)
    return jsonify({"output": result.decode()})

@app.route("/token")
def generate_token():
    # B311 — insecure random (CWE-330)
    token = random.randint(100000, 999999)
    return jsonify({"token": token})

if __name__ == "__main__":
    # B201 — debug=True (CWE-94)
    app.run(debug=True)