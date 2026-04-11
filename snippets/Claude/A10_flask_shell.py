import subprocess
import shlex
import logging
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Commands that are explicitly blocked for safety
BLOCKED_COMMANDS = {
    "rm", "mkfs", "dd", "shutdown", "reboot", "halt",
    "fdisk", "format", "del", "rmdir"
}


def is_blocked(command: str) -> bool:
    """Check if the command starts with a blocked keyword."""
    try:
        parts = shlex.split(command)
        if not parts:
            return False
        base_cmd = parts[0].split("/")[-1]  # handle full paths like /bin/rm
        return base_cmd in BLOCKED_COMMANDS
    except ValueError:
        return False


@app.route("/execute", methods=["POST"])
def execute_command():
    """
    Execute a shell command.

    Request body (JSON):
        {
            "command": "ls -la",
            "timeout": 10        # optional, default 10s, max 60s
        }

    Response (JSON):
        {
            "command": "ls -la",
            "stdout": "...",
            "stderr": "...",
            "returncode": 0,
            "success": true,
            "executed_at": "2025-01-01T12:00:00"
        }
    """
    data = request.get_json(silent=True)

    if not data or "command" not in data:
        return jsonify({"error": "Missing 'command' in request body"}), 400

    command = data["command"].strip()
    timeout = min(int(data.get("timeout", 10)), 60)  # cap at 60 seconds

    if not command:
        return jsonify({"error": "Command cannot be empty"}), 400

    if is_blocked(command):
        logger.warning(f"Blocked command attempt: {command}")
        return jsonify({"error": f"Command is blocked for safety reasons"}), 403

    logger.info(f"Executing command: {command}")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return jsonify({
            "command": command,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "success": result.returncode == 0,
            "executed_at": datetime.utcnow().isoformat()
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "error": f"Command timed out after {timeout} seconds",
            "command": command
        }), 408

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


@app.route("/blocked-commands", methods=["GET"])
def blocked_commands():
    """Return the list of blocked commands."""
    return jsonify({"blocked_commands": sorted(BLOCKED_COMMANDS)})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)