import os
from flask import Flask, request, abort, Response
from markupsafe import escape

app = Flask(__name__)

# Define a strict base directory (ONLY files inside this directory are accessible)
BASE_DIR = os.path.realpath(os.environ.get("SAFE_FILE_BASE_DIR", "./safe_files"))

@app.route('/read-file', methods=['GET'])
def read_file():
    file_path = request.args.get('path')

    if not file_path:
        abort(400, description="Missing file path")

    try:
        # Resolve absolute path
        requested_path = os.path.realpath(os.path.join(BASE_DIR, file_path))

        # Enforce boundary check (prevent path traversal)
        if not requested_path.startswith(BASE_DIR):
            abort(403, description="Access denied")

        # Ensure file exists and is a file
        if not os.path.isfile(requested_path):
            abort(404, description="File not found")

        # Read file safely
        with open(requested_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Escape content before returning (prevent XSS)
        safe_content = escape(content)

        return Response(safe_content, mimetype='text/plain')

    except Exception:
        # Generic error (no sensitive info leak)
        abort(500, description="Internal server error")


if __name__ == '__main__':
    app.run(debug=False)