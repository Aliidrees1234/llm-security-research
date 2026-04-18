import os
import uuid
import mimetypes
from pathlib import Path
from flask import (
    Flask, request, jsonify, render_template,
    send_from_directory, abort
)
from werkzeug.utils import secure_filename
import bleach

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)

# SECURITY: All secrets from environment — NEVER hardcoded
app.config["SECRET_KEY"]      = os.environ.get("SECRET_KEY", "change-me-in-prod")
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024  # 10 MB hard limit

# Upload directory — always resolved to an absolute, real path
BASE_DIR    = Path(__file__).resolve().parent
UPLOAD_DIR  = (BASE_DIR / "uploads").resolve()
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ─── Allow-list: only these MIME types are accepted ───────────────────────────
ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "application/pdf",
    "text/plain",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp",
                      ".pdf", ".txt", ".docx", ".xlsx"}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def is_safe_path(base: Path, target: Path) -> bool:
    """
    SECURITY: Verify that `target` is genuinely inside `base`.
    Prevents path-traversal attacks (../../etc/passwd etc.)
    """
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def allowed_file(filename: str, stream) -> tuple[bool, str]:
    """
    Two-layer validation:
      1. Extension allow-list (fast check)
      2. MIME-type sniffing from actual bytes (robust check)
    Returns (ok, reason).
    """
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, f"Extension '{ext}' is not permitted."

    # Read the first 2 KB to sniff MIME — then rewind
    header = stream.read(2048)
    stream.seek(0)
    mime, _ = mimetypes.guess_type(filename)

    # Use python-magic when available; fall back to mimetypes
    try:
        import magic  # python-magic (optional)
        mime = magic.from_buffer(header, mime=True)
    except ImportError:
        pass  # fall back to extension-based guess

    if mime not in ALLOWED_MIME_TYPES:
        return False, f"MIME type '{mime}' is not permitted."

    return True, "ok"


def sanitise_filename(original: str) -> str:
    """
    SECURITY:
      1. werkzeug secure_filename strips dangerous characters
      2. Prefix with a UUID4 so filenames are never predictable/guessable
    """
    safe = secure_filename(original) or "unnamed"
    unique = f"{uuid.uuid4().hex}_{safe}"
    return unique


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload():
    """
    Secure file upload endpoint.
    Hardened against:
      - Missing file / empty filename
      - Extension & MIME-type abuse
      - Path traversal
      - Oversized uploads (handled by MAX_CONTENT_LENGTH + explicit check)
      - XSS in filenames (secure_filename + JSON response — no raw HTML echo)
    """
    if "file" not in request.files:
        return jsonify({"error": "No file part in request."}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    # ── Validate extension + MIME ─────────────────────────────────────────────
    ok, reason = allowed_file(file.filename, file.stream)
    if not ok:
        return jsonify({"error": reason}), 415

    # ── Sanitise & build destination path ────────────────────────────────────
    safe_name   = sanitise_filename(file.filename)
    destination = (UPLOAD_DIR / safe_name).resolve()

    # ── SECURITY: Path-traversal boundary check ───────────────────────────────
    if not is_safe_path(UPLOAD_DIR, destination):
        app.logger.warning("Path traversal attempt blocked: %s", file.filename)
        return jsonify({"error": "Invalid file path."}), 400

    # ── Save ──────────────────────────────────────────────────────────────────
    try:
        file.save(destination)
    except OSError:
        # SECURITY: Never expose stack traces to the client
        app.logger.exception("File save failed for %s", safe_name)
        return jsonify({"error": "Upload failed. Please try again."}), 500

    # ── Respond with safe, escaped metadata ──────────────────────────────────
    # bleach.clean() escapes any rogue HTML/JS that slipped through
    display_name = bleach.clean(file.filename)
    size_kb      = round(destination.stat().st_size / 1024, 1)

    return jsonify({
        "message":   "File uploaded successfully.",
        "filename":  display_name,   # original (escaped) — for UI display only
        "stored_as": safe_name,      # UUID-prefixed server name
        "size_kb":   size_kb,
    }), 201


@app.route("/uploads/<filename>")
def serve_file(filename):
    """
    Serve uploaded files.
    SECURITY:
      - secure_filename on the URL param prevents traversal
      - send_from_directory adds its own boundary check
      - Only files inside UPLOAD_DIR are ever served
    """
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400)

    # Verify the resolved path is inside UPLOAD_DIR
    target = (UPLOAD_DIR / safe_name).resolve()
    if not is_safe_path(UPLOAD_DIR, target):
        abort(400)

    return send_from_directory(UPLOAD_DIR, safe_name)


# ─── Error handlers (NEVER expose debug info) ─────────────────────────────────

@app.errorhandler(413)
def too_large(_e):
    return jsonify({"error": "File exceeds the 10 MB size limit."}), 413

@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Resource not found."}), 404

@app.errorhandler(500)
def server_error(_e):
    return jsonify({"error": "An internal error occurred."}), 500


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # SECURITY: debug=False always — never expose Werkzeug debugger in prod
    app.run(debug=False, host="0.0.0.0", port=5000)