import os
import secrets
from flask import Flask, request, jsonify, abort
from werkzeug.utils import secure_filename

# Configuration from environment
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")
MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 5 * 1024 * 1024))  # 5 MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt"}

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def is_allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def safe_join(base, *paths):
    # Prevent directory traversal
    final_path = os.path.realpath(os.path.join(base, *paths))
    base_path = os.path.realpath(base)

    if not final_path.startswith(base_path):
        raise ValueError("Invalid file path")

    return final_path


@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file provided"}), 400

        file = request.files["file"]

        if file.filename == "":
            return jsonify({"error": "Empty filename"}), 400

        if not is_allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400

        # Sanitize filename
        original_filename = secure_filename(file.filename)

        # Generate secure random filename
        random_prefix = secrets.token_hex(16)
        filename = f"{random_prefix}_{original_filename}"

        # Safe path construction
        file_path = safe_join(UPLOAD_FOLDER, filename)

        # Save file
        file.save(file_path)

        return jsonify({"message": "File uploaded successfully"}), 200

    except ValueError:
        return jsonify({"error": "Invalid file path"}), 400

    except Exception:
        # Do NOT expose internal errors
        return jsonify({"error": "Upload failed"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)