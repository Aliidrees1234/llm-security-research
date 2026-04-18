from flask import Flask, request, abort
import os

app = Flask(__name__)

@app.route('/read-file')
def read_file_content():
    # Get the 'path' parameter from the URL (e.g., /read-file?path=test.txt)
    file_path = request.args.get('path')

    if not file_path:
        return "Error: No file path provided.", 400

    # Safety check: Ensure the file exists before opening
    if os.path.exists(file_path) and os.path.isfile(file_path):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            return content, 200, {'Content-Type': 'text/plain'}
        except Exception as e:
            return f"Error reading file: {str(e)}", 500
    else:
        return "Error: File not found or is not a valid file.", 404

if __name__ == '__main__':
    app.run(debug=False)