from flask import Flask, jsonify
import subprocess

app = Flask(__name__)

# Define a whitelist of allowed actions
ALLOWED_TASKS = {
    "disk_usage": ["df", "-h"],
    "uptime": ["uptime"]
}

@app.route('/run-task/<task_name>', methods=['GET'])
def run_task(task_name):
    # 1. Validate the input against a predefined list
    if task_name not in ALLOWED_TASKS:
        return jsonify({"error": "Unauthorized or unknown task"}), 400

    try:
        # 2. Use subprocess.run with shell=False (default) 
        # Passing arguments as a list prevents shell injection.
        result = subprocess.run(
            ALLOWED_TASKS[task_name], 
            capture_output=True, 
            text=True, 
            check=True
        )
        return jsonify({
            "task": task_name,
            "output": result.stdout.strip()
        })
    except subprocess.CalledProcessError as e:
        return jsonify({"error": "Task failed", "details": e.stderr}), 500

if __name__ == '__main__':
    app.run(debug=False)