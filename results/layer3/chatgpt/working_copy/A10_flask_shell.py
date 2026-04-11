from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/run", methods=["POST"])
def run_command():
    command = request.json.get("command")

    try:
        result = subprocess.check_output(command, shell=False, stderr=subprocess.STDOUT)
        return jsonify({"output": result.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output.decode()})

if __name__ == "__main__":
    app.run(debug=False)
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

ALLOWED_COMMANDS = {
    "list_files": ["ls", "-la"],
    "current_dir": ["pwd"],
    "whoami": ["whoami"]
}

@app.route("/run", methods=["POST"])
def run_command():

    cmd_key = request.json.get("command")

    if cmd_key not in ALLOWED_COMMANDS:
        return jsonify({"error": "Command not allowed"}), 403

    try:
        result = subprocess.check_output(ALLOWED_COMMANDS[cmd_key])
        return jsonify({"output": result.decode()})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(debug=False)

