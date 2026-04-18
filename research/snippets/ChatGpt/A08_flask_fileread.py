from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/read-file', methods=['GET'])
def read_file():
    file_path = request.args.get('path')

    if not file_path:
        return jsonify({"error": "No file path provided"}), 400

    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return jsonify({
            "path": file_path,
            "content": content
        })
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

import os
from flask import abort

BASE_DIR = os.path.abspath("files")

@app.route('/safe-read')
def safe_read():
    file_path = request.args.get('path')

    full_path = os.path.abspath(os.path.join(BASE_DIR, file_path))

    if not full_path.startswith(BASE_DIR):
        abort(403)

    with open(full_path, 'r') as f:
        return f.read()
    
