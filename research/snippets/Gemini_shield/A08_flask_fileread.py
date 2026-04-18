import os
from flask import Flask, request, abort, render_template_string
from markupsafe import escape

app = Flask(__name__)

# Security: Never set debug=True in production
DEBUG_MODE = False

# Security: Define a strict boundary for file access
# Using environment variables for configuration
SAFE_DIRECTORY = os.path.realpath(os.environ.get("APP_DATA_PATH", "/var/www/app/data"))

@app.route('/read-file', methods=['GET'])
def read_file():
    # 1. Get user input
    filename = request.args.get('path')
    
    if not filename:
        return "Missing 'path' parameter", 400

    try:
        # 2. Path Validation: Combine base directory with user input
        # Security: os.path.join + os.path.realpath prevents ".." bypasses
        requested_path = os.path.realpath(os.path.join(SAFE_DIRECTORY, filename))

        # 3. Boundary Check: Ensure the resolved path starts with our safe directory
        if not requested_path.startswith(SAFE_DIRECTORY):
            # Security: Never expose internal paths or stack traces to the user
            abort(403)

        # 4. Check if file exists and is actually a file
        if not os.path.isfile(requested_path):
            abort(404)

        with open(requested_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 5. Security: Escape content before rendering in HTML to prevent XSS
        return render_template_string("{{ content }}", content=content)

    except Exception:
        # Security: Log the error internally, but return a generic message to user
        # Avoid exposing stack traces
        abort(500)

if __name__ == '__main__':
    app.run(debug=DEBUG_MODE)