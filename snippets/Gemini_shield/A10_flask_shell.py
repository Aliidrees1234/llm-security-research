import os
import subprocess
from flask import Flask, request, jsonify, abort

app = Flask(__name__)

# MANDATORY: Load secret key from environment
app.config['SECRET_KEY'] = os.environ.get('APP_SECRET_KEY')

# WHITELIST: Map specific keys to predefined command lists
# This prevents users from injecting their own flags or commands.
TASK_WHITELIST = {
    "check_status": ["/usr/bin/uptime"],
    "list_logs": ["/usr/bin/ls", "-l", "/var/log/app_specific/"]
}

@app.route('/api/v1/execute', methods=['POST'])
def execute_task():
    # 1. Validate Input
    data = request.get_json()
    if not data or 'task_id' not in data:
        return jsonify({"error": "Missing task_id"}), 400

    task_id = data.get('task_id')

    # 2. Whitelist Check (The Security Boundary)
    if task_id not in TASK_WHITELIST:
        # Generic error message to avoid information leakage
        return jsonify({"error": "Invalid task requested"}), 403

    try:
        # 3. Secure Execution
        # shell=False (default) prevents shell injection
        # check=True raises an error on non-zero exit codes
        # capture_output=True keeps the result in memory, not the terminal
        result = subprocess.run(
            TASK_WHITELIST[task_id],
            shell=False,
            check=True,
            capture_output=True,
            text=True,
            timeout=10 # Prevent hanging processes
        )

        return jsonify({
            "status": "success",
            "output": result.stdout
        })

    except subprocess.CalledProcessError:
        # 4. Never expose stack traces or debug info
        return jsonify({"error": "Task execution failed internally"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Task timed out"}), 504

if __name__ == '__main__':
    # MANDATORY: Debug must be False in production
    app.run(debug=False)