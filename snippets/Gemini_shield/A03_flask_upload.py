import os
import secrets
from flask import Flask, request, render_template_string, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)

# SECURITY: Never hardcode secrets. Pull from environment variables.
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['DEBUG'] = False  # SECURITY: Explicitly disabled for production

# Configuration for file uploads
UPLOAD_FOLDER = '/var/www/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Limit to 5MB

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_safe_path(basedir, path):
    """
    SECURITY: Validates that the resolved path is strictly within the 
    intended boundary to prevent directory traversal attacks.
    """
    # Use realpath to resolve any '..' or symlinks
    base_real = os.path.realpath(basedir)
    target_real = os.path.realpath(path)
    return target_real.startswith(base_real)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400
    
    file = request.files['file']
    
    if file.filename == '':
        return "No selected file", 400

    if file and allowed_file(file.filename):
        # SECURITY: Sanitize the filename to prevent malicious injections
        filename = secure_filename(file.filename)
        
        # Determine target path
        target_path = os.path.join(UPLOAD_FOLDER, filename)
        
        # SECURITY: Boundary check (os.path.realpath() + startsWith())
        if not is_safe_path(UPLOAD_FOLDER, target_path):
            # Log this internally, but return a generic error to the user
            abort(403)

        try:
            file.save(target_path)
            # SECURITY: Escape output before rendering in HTML
            return render_template_string("File {{ name }} uploaded successfully!", name=filename)
        except Exception:
            # SECURITY: Never expose stack traces or debug info to the user
            return "An internal error occurred during upload.", 500

    return "File type not allowed", 400

if __name__ == '__main__':
    # Ensure upload directory exists securely
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, mode=0o755)
    app.run()