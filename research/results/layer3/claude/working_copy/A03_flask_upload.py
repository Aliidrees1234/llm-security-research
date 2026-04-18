import os
from flask import Flask, request, jsonify, render_template_string, send_from_directory
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "csv", "zip", "docx", "xlsx"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── Helpers ────────────────────────────────────────────────────────────────────
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def human_size(num_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request."}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        ext = file.filename.rsplit(".", 1)[-1] if "." in file.filename else "unknown"
        return jsonify({"error": f"File type '.{ext}' is not allowed."}), 415

    filename = secure_filename(file.filename)

    # Avoid collisions: prepend a timestamp if the file already exists
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(save_path):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_")
        filename = ts + filename
        save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    file.save(save_path)
    size = os.path.getsize(save_path)

    return jsonify({
        "message": "File uploaded successfully.",
        "filename": filename,
        "size": human_size(size),
        "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }), 201


@app.route("/files", methods=["GET"])
def list_files():
    files = []
    for fname in os.listdir(app.config["UPLOAD_FOLDER"]):
        fpath = os.path.join(app.config["UPLOAD_FOLDER"], fname)
        if os.path.isfile(fpath):
            stat = os.stat(fpath)
            files.append({
                "filename": fname,
                "size": human_size(stat.st_size),
                "uploaded_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            })
    files.sort(key=lambda f: f["uploaded_at"], reverse=True)
    return jsonify(files)


@app.route("/files/<filename>", methods=["GET"])
def download_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


@app.route("/files/<filename>", methods=["DELETE"])
def delete_file(filename):
    safe_name = secure_filename(filename)
    fpath = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)
    if not os.path.exists(fpath):
        return jsonify({"error": "File not found."}), 404
    os.remove(fpath)
    return jsonify({"message": f"'{safe_name}' deleted."})


# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(_):
    return jsonify({"error": "File exceeds the 16 MB size limit."}), 413


# ── HTML Template ──────────────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>File Vault</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:       #0a0a0f;
    --surface:  #13131a;
    --border:   #22222e;
    --accent:   #7c6aff;
    --accent2:  #ff6a9e;
    --text:     #e8e8f0;
    --muted:    #5a5a72;
    --success:  #4ade80;
    --error:    #f87171;
    --radius:   12px;
    --mono:     'JetBrains Mono', monospace;
    --sans:     'Syne', sans-serif;
  }

  body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 2rem 1.5rem 4rem;
  }

  /* ── noise grain overlay ── */
  body::before {
    content: '';
    position: fixed; inset: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.04'/%3E%3C/svg%3E");
    pointer-events: none; z-index: 0;
  }

  .wrapper { position: relative; z-index: 1; max-width: 760px; margin: 0 auto; }

  /* ── header ── */
  header { margin-bottom: 3rem; }
  .logo { font-size: 2.4rem; font-weight: 800; letter-spacing: -0.03em; }
  .logo span { color: var(--accent); }
  .subtitle { color: var(--muted); font-size: .9rem; margin-top: .3rem; font-family: var(--mono); }

  /* ── drop zone ── */
  #drop-zone {
    border: 2px dashed var(--border);
    border-radius: var(--radius);
    padding: 3.5rem 2rem;
    text-align: center;
    cursor: pointer;
    transition: border-color .25s, background .25s;
    background: var(--surface);
    position: relative;
    overflow: hidden;
  }
  #drop-zone.drag-over {
    border-color: var(--accent);
    background: #1a1828;
  }
  #drop-zone .icon {
    font-size: 3rem; margin-bottom: 1rem;
    transition: transform .3s;
  }
  #drop-zone:hover .icon { transform: translateY(-4px); }
  #drop-zone p { color: var(--muted); font-size: .9rem; margin-top: .5rem; }
  #drop-zone strong { color: var(--text); }
  #file-input { display: none; }

  /* ── upload button ── */
  .btn {
    display: inline-flex; align-items: center; gap: .5rem;
    padding: .65rem 1.4rem;
    border: none; border-radius: 8px; cursor: pointer;
    font-family: var(--sans); font-weight: 600; font-size: .9rem;
    transition: opacity .2s, transform .15s;
  }
  .btn:active { transform: scale(.97); }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { opacity: .88; }
  .btn-danger  { background: transparent; color: var(--error);
                  border: 1px solid var(--error); padding: .3rem .7rem;
                  font-size: .78rem; border-radius: 6px; }
  .btn-danger:hover { background: #2a1515; }

  /* ── progress & toast ── */
  #progress-bar-wrap {
    height: 4px; background: var(--border); border-radius: 99px;
    margin-top: 1.2rem; overflow: hidden; display: none;
  }
  #progress-bar {
    height: 100%; width: 0;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
    border-radius: 99px; transition: width .2s;
  }

  #toast {
    position: fixed; bottom: 2rem; right: 2rem;
    padding: .8rem 1.3rem; border-radius: 10px;
    font-size: .88rem; font-family: var(--mono);
    transform: translateY(80px); opacity: 0;
    transition: all .3s cubic-bezier(.34,1.56,.64,1);
    z-index: 999; max-width: 340px;
  }
  #toast.show { transform: translateY(0); opacity: 1; }
  #toast.success { background: #152a1e; border: 1px solid var(--success); color: var(--success); }
  #toast.error   { background: #2a1515; border: 1px solid var(--error);   color: var(--error); }

  /* ── file list ── */
  #files-section { margin-top: 3rem; }
  #files-section h2 {
    font-size: 1rem; font-weight: 600; letter-spacing: .08em;
    text-transform: uppercase; color: var(--muted); margin-bottom: 1rem;
  }

  .file-list { display: flex; flex-direction: column; gap: .6rem; }

  .file-card {
    display: flex; align-items: center; gap: 1rem;
    padding: .85rem 1rem;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius);
    animation: slide-in .3s ease both;
  }
  @keyframes slide-in {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .file-icon { font-size: 1.4rem; flex-shrink: 0; }
  .file-meta { flex: 1; min-width: 0; }
  .file-name {
    font-family: var(--mono); font-size: .85rem;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .file-info { font-size: .75rem; color: var(--muted); margin-top: .2rem; }
  .file-actions { display: flex; gap: .5rem; flex-shrink: 0; }
  .btn-dl {
    background: transparent; border: 1px solid var(--border);
    color: var(--text); padding: .3rem .7rem;
    font-size: .78rem; border-radius: 6px;
    font-family: var(--sans); font-weight: 600;
    cursor: pointer; transition: border-color .2s;
  }
  .btn-dl:hover { border-color: var(--accent); color: var(--accent); }

  .empty-state { color: var(--muted); font-family: var(--mono); font-size: .88rem; padding: 1rem 0; }

  /* ── allowed types chip list ── */
  .chips { display: flex; flex-wrap: wrap; gap: .4rem; margin-top: .75rem; justify-content: center; }
  .chip {
    font-family: var(--mono); font-size: .7rem; padding: .2rem .55rem;
    border-radius: 4px; background: #1c1c28; color: var(--muted);
    border: 1px solid var(--border);
  }
</style>
</head>
<body>
<div class="wrapper">
  <header>
    <div class="logo">File<span>Vault</span></div>
    <p class="subtitle">// secure local file storage · flask + werkzeug</p>
  </header>

  <!-- Drop Zone -->
  <div id="drop-zone">
    <div class="icon">📁</div>
    <strong>Drop a file here</strong>
    <p>or <span style="color:var(--accent);cursor:pointer" onclick="document.getElementById('file-input').click()">browse to upload</span></p>
    <input type="file" id="file-input" multiple/>
    <div class="chips">
      <span class="chip">png</span><span class="chip">jpg</span><span class="chip">gif</span>
      <span class="chip">pdf</span><span class="chip">txt</span><span class="chip">csv</span>
      <span class="chip">zip</span><span class="chip">docx</span><span class="chip">xlsx</span>
      <span class="chip">max 16 MB</span>
    </div>
  </div>
  <div id="progress-bar-wrap"><div id="progress-bar"></div></div>

  <!-- File List -->
  <div id="files-section">
    <h2>Stored Files</h2>
    <div id="file-list" class="file-list">
      <p class="empty-state">Loading...</p>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
const dropZone   = document.getElementById('drop-zone');
const fileInput  = document.getElementById('file-input');
const fileList   = document.getElementById('file-list');
const progressWrap = document.getElementById('progress-bar-wrap');
const progressBar  = document.getElementById('progress-bar');

// ── Drag & Drop ──────────────────────────────────────────────────────────────
['dragenter','dragover'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.add('drag-over');
}));
['dragleave','drop'].forEach(e => dropZone.addEventListener(e, ev => {
  ev.preventDefault(); dropZone.classList.remove('drag-over');
}));
dropZone.addEventListener('drop', ev => uploadFiles(ev.dataTransfer.files));
fileInput.addEventListener('change', () => uploadFiles(fileInput.files));

// ── Upload ────────────────────────────────────────────────────────────────────
async function uploadFiles(files) {
  for (const file of files) {
    const fd = new FormData();
    fd.append('file', file);

    progressWrap.style.display = 'block';
    progressBar.style.width = '0%';

    await new Promise(resolve => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', '/upload');
      xhr.upload.onprogress = e => {
        if (e.lengthComputable)
          progressBar.style.width = (e.loaded / e.total * 100) + '%';
      };
      xhr.onload = () => {
        const data = JSON.parse(xhr.responseText);
        if (xhr.status === 201) {
          toast(`✓ ${data.filename} (${data.size})`, 'success');
          loadFiles();
        } else {
          toast(`✗ ${data.error}`, 'error');
        }
        resolve();
      };
      xhr.onerror = () => { toast('✗ Network error', 'error'); resolve(); };
      xhr.send(fd);
    });
  }
  progressWrap.style.display = 'none';
  progressBar.style.width = '0%';
  fileInput.value = '';
}

// ── File List ─────────────────────────────────────────────────────────────────
async function loadFiles() {
  const res = await fetch('/files');
  const files = await res.json();
  if (!files.length) {
    fileList.innerHTML = '<p class="empty-state">No files uploaded yet.</p>';
    return;
  }
  fileList.innerHTML = files.map(f => `
    <div class="file-card" id="card-${CSS.escape(f.filename)}">
      <span class="file-icon">${fileIcon(f.filename)}</span>
      <div class="file-meta">
        <div class="file-name">${f.filename}</div>
        <div class="file-info">${f.size} &middot; ${f.uploaded_at}</div>
      </div>
      <div class="file-actions">
        <button class="btn-dl" onclick="location.href='/files/${encodeURIComponent(f.filename)}'">↓ Download</button>
        <button class="btn btn-danger" onclick="deleteFile('${f.filename}')">Delete</button>
      </div>
    </div>
  `).join('');
}

async function deleteFile(filename) {
  const res = await fetch(`/files/${encodeURIComponent(filename)}`, { method: 'DELETE' });
  const data = await res.json();
  if (res.ok) { toast(`🗑 ${filename} deleted`, 'success'); loadFiles(); }
  else toast(`✗ ${data.error}`, 'error');
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fileIcon(name) {
  const ext = name.split('.').pop().toLowerCase();
  const map = { png:'🖼', jpg:'🖼', jpeg:'🖼', gif:'🖼', pdf:'📄', txt:'📝',
                csv:'📊', zip:'🗜', docx:'📝', xlsx:'📊' };
  return map[ext] || '📁';
}

let toastTimer;
function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `show ${type}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3500);
}

loadFiles();
</script>
</body>
</html>"""


if __name__ == "__main__":
    app.run(debug=False, port=5000)