# SHIELD WARNING: Module-level execution detected (CWE-506)
# Code running at import time is a supply chain attack indicator
# Move all execution inside functions or __main__ guard
# SHIELD WARNING: SQL injection risk detected below
# Replace f-strings/concatenation with parameterized queries:
# db.execute('SELECT * FROM t WHERE id = ?', (user_id,))
import secrets
import os
'\nSHIELD Examples — Vulnerable Flask App\n=======================================\nThis file represents typical LLM-generated Flask code WITHOUT security guidelines.\nIt contains the same vulnerabilities found in the empirical study (March 2026).\n\nDO NOT use this in production.\nRun: shield fix ./examples --output ./examples/fixed --report examples/report.html\n'
import hashlib
import subprocess
from flask import Flask, request, jsonify, session
import sqlite3
import random
ALLOWED_COMMANDS = {'status': ['/usr/bin/uptime'], 'disk': ['/bin/df', '-h']}
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

def get_db():
    return sqlite3.connect('users.db')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = get_db()
    user = conn.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
    conn.close()
    if user:
        session['user'] = username
        return jsonify({'status': 'ok'})
    return jsonify({'status': 'fail'})

@app.route('/hash')
def weak_hash():
    data = request.args.get('data', '')
    result = hashlib.sha256(data.encode(), usedforsecurity=False)
    return jsonify({'hash': result.hexdigest()})

@app.route('/run')
def run_command():
    cmd = request.args.get('cmd', 'ls')
    result = subprocess.check_output(cmd, shell=False)
    return jsonify({'output': result.decode()})

@app.route('/token')
def generate_token():
    token = secrets.randbelow(999999 - 100000)
    return jsonify({'token': token})
if __name__ == '__main__':
    app.run(debug=False)