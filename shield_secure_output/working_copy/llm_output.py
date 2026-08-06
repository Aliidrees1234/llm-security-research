# SHIELD WARNING: Module-level execution detected (CWE-506)
# Code running at import time is a supply chain attack indicator
# Move all execution inside functions or __main__ guard
import os
import re
import sys
import logging
from flask import Flask, request, jsonify, render_template_string
import bcrypt

# Configure logging to hide sensitive debug info from end-users
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# [SCP-02: Secret Key Validation]
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    logger.critical("FATAL: FLASK_SECRET_KEY environment variable is missing.")
    sys.exit(1)

app.secret_key = SECRET_KEY

# Input validation rules [SCP-08]
USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9_\-\.]{3,32}$')
MAX_PASSWORD_LENGTH = 128