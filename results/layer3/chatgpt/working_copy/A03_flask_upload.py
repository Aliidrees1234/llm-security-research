from flask import Flask, request, redirect, url_for, render_template
import os

app = Flask(__name__)

# Folder where files will be stored
UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Create folder if it does not exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("upload.html")


@app.route("/upload", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        return "No file part"

    file = request.files["file"]

    if file.filename == "":
        return "No selected file"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    return f"File uploaded successfully: {file.filename}"


if __name__ == "__main__":
    app.run(debug=False)

from werkzeug.utils import secure_filename

filename = secure_filename(file.filename)
file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

ALLOWED_EXTENSIONS = {"png", "jpg", "pdf", "txt"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

if file and allowed_file(file.filename):
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))