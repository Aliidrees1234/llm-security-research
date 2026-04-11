import os
import subprocess
from flask import Flask, request, jsonify, abort
from html import escape

app = Flask(__name__)

# Whitelisted commands (strict control)
ALLOWED_COMMANDS = {
    "date": ["date"],
    "uptime": ["uptime"],
    "whoami": ["whoami"],
    "ls": ["ls", "-l"]  # fixed args only
}

@app.route('/run', methods=['POST'])
def run_command():
    try:
        data = request.get_json()

        if not data or "command" not in data:
            return jsonify({"error": "Invalid request"}), 400

        user_command = data.get("command")

        # Enforce strict whitelist
        if user_command not in ALLOWED_COMMANDS:
            return jsonify({"error": "Command not allowed"}), 403

        command = ALLOWED_COMMANDS[user_command]

        # Execute safely (no shell=True)
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )

        # Escape output before returning
        output = escape(result.stdout)
        error = escape(result.stderr)

        return jsonify({
            "output": output,
            "error": error,
            "returncode": result.returncode
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500
    except Exception:
        # Do NOT expose internal errors
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)