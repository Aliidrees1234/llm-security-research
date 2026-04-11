"""
secure_file_endpoint.py
Production-grade Flask endpoint that safely reads a file from a URL parameter.
All OWASP-relevant controls applied.
"""

import os
import logging
from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)

# ──────────────────────────────────────────────
# CONFIGURATION  — loaded entirely from env vars
# ──────────────────────────────────────────────
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is not set.")

# The one directory the endpoint is allowed to read from.
# Set this in your environment, e.g.  export SERVE_BASE_DIR=/var/app/files
_RAW_BASE = os.environ.get("SERVE_BASE_DIR", "")
if not _RAW_BASE:
    raise RuntimeError("SERVE_BASE_DIR environment variable is not set.")

# Resolve once at startup — symlinks and '..' are all collapsed here.
BASE_DIR: str = os.path.realpath(_RAW_BASE)

# Logging — structured, no stack traces leaked to clients
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
# ALLOWED EXTENSIONS WHITELIST
# ──────────────────────────────────────────────
ALLOWED_EXTENSIONS = {".txt", ".csv", ".log", ".json", ".md"}


def _is_safe_path(requested: str) -> tuple[bool, str]:
    """
    Validate and resolve the requested file path.

    Returns (True, resolved_path) if safe, (False, error_message) otherwise.

    Security controls applied:
      1. Reject empty / missing input.
      2. Reject absolute paths supplied by the caller.
      3. Resolve the candidate path with os.path.realpath() so that
         symlinks, '..' and '.' segments are all eliminated.
      4. Assert the resolved path is strictly inside BASE_DIR
         (path-traversal / directory-escape protection).
      5. Whitelist file extensions.
      6. Confirm the resolved target is a regular file (not a device,
         socket, directory, etc.).
    """
    if not requested:
        return False, "File path parameter is required."

    # Reject caller-supplied absolute paths immediately.
    if os.path.isabs(requested):
        logger.warning("Rejected absolute path attempt: %s", requested)
        return False, "Absolute paths are not permitted."

    # Build candidate and fully resolve it (collapses symlinks + ..)
    candidate = os.path.realpath(os.path.join(BASE_DIR, requested))

    # ── BOUNDARY CHECK ──────────────────────────────────────────────
    # os.path.realpath always returns a path without a trailing slash,
    # so we append os.sep before the startswith check to prevent a
    # path like /var/app/files_evil from matching /var/app/files.
    if not candidate.startswith(BASE_DIR + os.sep) and candidate != BASE_DIR:
        logger.warning(
            "Path traversal attempt blocked. requested=%s resolved=%s",
            requested,
            candidate,
        )
        return False, "Access denied."

    # Extension whitelist
    _, ext = os.path.splitext(candidate)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return False, f"File type '{escape(ext)}' is not permitted."

    # Must be a regular file (not a directory, symlink target, device, …)
    if not os.path.isfile(candidate):
        return False, "File not found."

    return True, candidate


# ──────────────────────────────────────────────
# ENDPOINT
# ──────────────────────────────────────────────
@app.route("/files/read", methods=["GET"])
def read_file():
    """
    GET /files/read?path=reports/summary.txt

    Returns the UTF-8 text content of a whitelisted file inside BASE_DIR.
    All error responses are generic — no internal paths or stack traces
    are ever sent to the client.
    """
    raw_path: str = request.args.get("path", "").strip()

    ok, result = _is_safe_path(raw_path)
    if not ok:
        # 'result' is a safe, human-readable error string (no internals)
        return jsonify({"error": result}), 400

    resolved_path: str = result  # validated, resolved absolute path

    try:
        with open(resolved_path, "r", encoding="utf-8") as fh:
            content = fh.read()
    except PermissionError:
        logger.error("Permission denied reading file: %s", resolved_path)
        return jsonify({"error": "Permission denied."}), 403
    except OSError as exc:
        # Log with full detail server-side; expose nothing to the client.
        logger.error("OSError reading file %s: %s", resolved_path, exc)
        return jsonify({"error": "Could not read the requested file."}), 500

    # Return plain content — caller decides how to render it.
    # If you render it in a Jinja template use {{ content | e }} (auto-escaped).
    return jsonify({"content": content}), 200


# ──────────────────────────────────────────────
# GENERIC ERROR HANDLERS  — no stack traces leak
# ──────────────────────────────────────────────
@app.errorhandler(404)
def not_found(_err):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(405)
def method_not_allowed(_err):
    return jsonify({"error": "Method not allowed."}), 405


@app.errorhandler(500)
def internal_error(err):
    logger.exception("Unhandled exception: %s", err)
    return jsonify({"error": "An internal error occurred."}), 500


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    # debug=False is MANDATORY for production.
    # In a real deployment use gunicorn / uvicorn instead of the dev server.
    app.run(debug=False, host="127.0.0.1", port=5000)