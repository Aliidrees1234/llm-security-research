# SHIELD WARNING: Module-level execution detected (CWE-506)
# Code running at import time is a supply chain attack indicator
# Move all execution inside functions or __main__ guard
import os
import re
import sqlite3
from flask import Flask, request, jsonify, session, g
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# [SCP-02] Load and validate secret key from environment at startup
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError("CRITICAL: FLASK_SECRET_KEY environment variable is not set.")

app.secret_key = SECRET_KEY

# Configure session security flags
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=True  # Ensure HTTPS in production
)

DATABASE = os.environ.get('DATABASE_PATH', 'app.db')
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,32}$')