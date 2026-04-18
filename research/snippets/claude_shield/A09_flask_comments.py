import os
import sqlite3
import html
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, abort
from markupsafe import escape

# ─── App Setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["DEBUG"] = False  # NEVER True in production

# ─── Logging (no stack traces to users) ───────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── Database ─────────────────────────────────────────────────────────────────
DB_PATH = os.environ.get("DB_PATH", "comments.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS comments (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                author    TEXT    NOT NULL CHECK(length(author)  BETWEEN 1 AND 80),
                body      TEXT    NOT NULL CHECK(length(body)    BETWEEN 1 AND 2000),
                likes     INTEGER NOT NULL DEFAULT 0,
                created_at TEXT   NOT NULL
            )
        """)
        conn.commit()

init_db()

# ─── Input Validation ─────────────────────────────────────────────────────────
def validate_comment(author: str, body: str) -> tuple[bool, str]:
    author = author.strip()
    body   = body.strip()

    if not author or len(author) > 80:
        return False, "Author must be 1–80 characters."
    if not body or len(body) > 2000:
        return False, "Comment must be 1–2000 characters."
    return True, ""

# ─── HTML Template ────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Comments</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,500;1,400&family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --ink:       #1a1208;
    --paper:     #f5f0e8;
    --cream:     #ede8dc;
    --amber:     #c97b2a;
    --amber-dim: #e8b46a;
    --rule:      #d4c9b0;
    --shadow:    rgba(26,18,8,.12);
    --red:       #b94040;
    --green:     #2e7d52;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'DM Sans', sans-serif;
    background: var(--paper);
    color: var(--ink);
    min-height: 100vh;
    padding: 2rem 1rem 5rem;
    background-image:
      repeating-linear-gradient(
        transparent,
        transparent 27px,
        var(--rule) 27px,
        var(--rule) 28px
      );
    background-attachment: local;
  }

  /* ── Page Header ─────────────────────────────── */
  .page-header {
    max-width: 760px;
    margin: 0 auto 3rem;
    padding-bottom: 1.5rem;
    border-bottom: 3px double var(--rule);
    display: flex;
    align-items: baseline;
    gap: 1.2rem;
  }
  .page-header h1 {
    font-family: 'Playfair Display', serif;
    font-size: clamp(2rem, 5vw, 3.2rem);
    letter-spacing: -.02em;
    line-height: 1;
  }
  .page-header .vol {
    font-family: 'DM Mono', monospace;
    font-size: .72rem;
    color: var(--amber);
    letter-spacing: .14em;
    text-transform: uppercase;
  }

  /* ── Form ────────────────────────────────────── */
  .form-card {
    max-width: 760px;
    margin: 0 auto 3rem;
    background: var(--cream);
    border: 1px solid var(--rule);
    border-top: 4px solid var(--amber);
    padding: 2rem 2.2rem;
    box-shadow: 4px 4px 0 var(--shadow);
    position: relative;
  }
  .form-card::before {
    content: 'NEW ENTRY';
    position: absolute;
    top: -1px; right: 1.8rem;
    background: var(--amber);
    color: #fff;
    font-family: 'DM Mono', monospace;
    font-size: .6rem;
    letter-spacing: .18em;
    padding: .2rem .7rem .15rem;
  }

  .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  @media(max-width:520px){ .form-row { grid-template-columns: 1fr; } }

  label {
    display: block;
    font-family: 'DM Mono', monospace;
    font-size: .68rem;
    letter-spacing: .12em;
    text-transform: uppercase;
    color: var(--amber);
    margin-bottom: .4rem;
  }

  input[type=text], textarea {
    width: 100%;
    background: var(--paper);
    border: 1px solid var(--rule);
    border-bottom: 2px solid var(--ink);
    padding: .65rem .85rem;
    font-family: 'DM Sans', sans-serif;
    font-size: .95rem;
    color: var(--ink);
    outline: none;
    transition: border-color .2s;
    resize: vertical;
  }
  input[type=text]:focus, textarea:focus {
    border-color: var(--amber);
    box-shadow: 0 2px 0 var(--amber);
  }

  .char-hint {
    font-family: 'DM Mono', monospace;
    font-size: .62rem;
    color: #888;
    text-align: right;
    margin-top: .25rem;
    height: 1em;
  }

  .submit-btn {
    margin-top: 1.4rem;
    background: var(--ink);
    color: var(--paper);
    border: none;
    padding: .75rem 2.2rem;
    font-family: 'DM Mono', monospace;
    font-size: .78rem;
    letter-spacing: .14em;
    text-transform: uppercase;
    cursor: pointer;
    transition: background .2s, transform .1s;
  }
  .submit-btn:hover  { background: var(--amber); }
  .submit-btn:active { transform: scale(.97); }

  /* ── Flash Messages ──────────────────────────── */
  .flash {
    max-width: 760px;
    margin: 0 auto 1.5rem;
    padding: .75rem 1.1rem;
    font-family: 'DM Mono', monospace;
    font-size: .78rem;
    letter-spacing: .06em;
    border-left: 4px solid;
  }
  .flash.error  { border-color: var(--red);   background:#fdf0f0; color:var(--red); }
  .flash.success{ border-color: var(--green); background:#f0fdf6; color:var(--green); }

  /* ── Comment Feed ────────────────────────────── */
  .feed { max-width: 760px; margin: 0 auto; }
  .feed-header {
    display: flex;
    align-items: center;
    gap: .8rem;
    margin-bottom: 1.5rem;
  }
  .feed-header h2 {
    font-family: 'Playfair Display', serif;
    font-size: 1.3rem;
    font-style: italic;
  }
  .feed-header .count-badge {
    background: var(--ink);
    color: var(--paper);
    font-family: 'DM Mono', monospace;
    font-size: .65rem;
    padding: .2rem .55rem;
    letter-spacing: .1em;
  }

  /* ── Comment Card ────────────────────────────── */
  .comment {
    background: var(--cream);
    border: 1px solid var(--rule);
    border-left: 4px solid var(--amber-dim);
    padding: 1.3rem 1.5rem;
    margin-bottom: 1.1rem;
    box-shadow: 2px 2px 0 var(--shadow);
    animation: slideIn .35s ease;
  }
  @keyframes slideIn {
    from { opacity:0; transform:translateY(8px); }
    to   { opacity:1; transform:translateY(0); }
  }

  .comment-meta {
    display: flex;
    align-items: baseline;
    gap: .8rem;
    margin-bottom: .7rem;
  }
  .comment-author {
    font-family: 'Playfair Display', serif;
    font-weight: 500;
    font-size: 1.05rem;
  }
  .comment-date {
    font-family: 'DM Mono', monospace;
    font-size: .62rem;
    color: #888;
    letter-spacing: .06em;
  }

  .comment-body {
    font-size: .95rem;
    line-height: 1.7;
    white-space: pre-wrap;
    word-break: break-word;
  }

  .comment-actions {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-top: 1rem;
    padding-top: .7rem;
    border-top: 1px solid var(--rule);
  }
  .like-btn {
    background: none;
    border: 1px solid var(--rule);
    padding: .3rem .8rem;
    font-family: 'DM Mono', monospace;
    font-size: .7rem;
    letter-spacing: .06em;
    cursor: pointer;
    color: var(--ink);
    transition: all .18s;
    display: flex;
    align-items: center;
    gap: .45rem;
  }
  .like-btn:hover  { border-color: var(--amber); color: var(--amber); }
  .like-btn.liked  { background: var(--amber); border-color: var(--amber); color: #fff; }
  .like-count      { font-weight: 500; }

  .delete-btn {
    background: none;
    border: none;
    cursor: pointer;
    color: #bbb;
    font-family: 'DM Mono', monospace;
    font-size: .68rem;
    letter-spacing: .06em;
    padding: .3rem .5rem;
    transition: color .18s;
    margin-left: auto;
  }
  .delete-btn:hover { color: var(--red); }

  /* ── Empty State ─────────────────────────────── */
  .empty {
    text-align: center;
    padding: 4rem 0;
    color: #aaa;
    font-family: 'Playfair Display', serif;
    font-style: italic;
    font-size: 1.1rem;
  }
  .empty::before {
    display: block;
    content: '— ✦ —';
    margin-bottom: 1rem;
    letter-spacing: .4em;
    font-style: normal;
    font-size: .9rem;
  }

  /* ── Spinner ─────────────────────────────────── */
  .spinner {
    width: 18px; height: 18px;
    border: 2px solid transparent;
    border-top-color: currentColor;
    border-radius: 50%;
    animation: spin .6s linear infinite;
    display: none;
  }
  .loading .spinner { display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>

<header class="page-header">
  <h1>The Comment Ledger</h1>
  <span class="vol">Vol. I &nbsp;·&nbsp; Open Edition</span>
</header>

<div id="flash-area"></div>

<!-- ── Submission Form ──────────────────────────────────── -->
<div class="form-card">
  <div style="margin-bottom:1.2rem;">
    <div class="form-row">
      <div>
        <label for="author">Your Name</label>
        <input type="text" id="author" maxlength="80" placeholder="Anonymous Reader" autocomplete="off">
      </div>
    </div>
  </div>
  <div>
    <label for="body">Your Remark</label>
    <textarea id="body" rows="4" maxlength="2000" placeholder="Leave your mark on the page…"></textarea>
    <div class="char-hint" id="char-hint"></div>
  </div>
  <button class="submit-btn" id="submit-btn" onclick="submitComment()">
    <span class="spinner" id="spinner"></span>
    <span id="btn-label">Publish Entry</span>
  </button>
</div>

<!-- ── Comment Feed ─────────────────────────────────────── -->
<div class="feed">
  <div class="feed-header">
    <h2>Reader Entries</h2>
    <span class="count-badge" id="count-badge">…</span>
  </div>
  <div id="comments-list"></div>
</div>

<script>
// Track liked comments in memory (page session only)
const liked = new Set();

/* ── Helpers ─────────────────────────────────────────── */
function esc(str) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(str));
  return d.innerHTML;
}

function flash(msg, type = 'error') {
  const el = document.getElementById('flash-area');
  el.innerHTML = `<div class="flash ${type}">${esc(msg)}</div>`;
  setTimeout(() => el.innerHTML = '', 4000);
}

function formatDate(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric',
    hour:'2-digit', minute:'2-digit' });
}

/* ── Render One Comment ──────────────────────────────── */
function renderComment(c) {
  const likedClass = liked.has(c.id) ? 'liked' : '';
  return `
    <div class="comment" id="comment-${c.id}">
      <div class="comment-meta">
        <span class="comment-author">${esc(c.author)}</span>
        <span class="comment-date">${formatDate(c.created_at)}</span>
      </div>
      <div class="comment-body">${esc(c.body)}</div>
      <div class="comment-actions">
        <button class="like-btn ${likedClass}" onclick="toggleLike(${c.id}, this)">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 21.35l-1.45-1.32C5.4 15.36 2 12.28 2 8.5 2 5.42 4.42 3 7.5 3c1.74 0 3.41.81 4.5 2.09C13.09 3.81 14.76 3 16.5 3 19.58 3 22 5.42 22 8.5c0 3.78-3.4 6.86-8.55 11.54L12 21.35z"/>
          </svg>
          <span class="like-count">${c.likes}</span>
        </button>
        <button class="delete-btn" onclick="deleteComment(${c.id})">✕ Remove</button>
      </div>
    </div>`;
}

/* ── Load Comments ───────────────────────────────────── */
async function loadComments() {
  try {
    const res  = await fetch('/api/comments');
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Failed to load');

    const list = document.getElementById('comments-list');
    document.getElementById('count-badge').textContent = data.length;

    if (data.length === 0) {
      list.innerHTML = '<div class="empty">No entries yet — be the first to leave a mark.</div>';
    } else {
      list.innerHTML = data.map(renderComment).join('');
    }
  } catch (e) {
    flash('Could not load comments. Please refresh.', 'error');
  }
}

/* ── Submit Comment ──────────────────────────────────── */
async function submitComment() {
  const author = document.getElementById('author').value.trim();
  const body   = document.getElementById('body').value.trim();

  if (!author) { flash('Please enter your name.'); return; }
  if (!body)   { flash('Comment cannot be empty.'); return; }

  const btn     = document.getElementById('submit-btn');
  const label   = document.getElementById('btn-label');
  const spinner = document.getElementById('spinner');

  btn.disabled   = true;
  label.textContent = 'Publishing…';
  spinner.style.display = 'inline-block';

  try {
    const res  = await fetch('/api/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ author, body })
    });
    const data = await res.json();
    if (!res.ok) { flash(data.error || 'Submission failed.'); return; }

    document.getElementById('author').value = '';
    document.getElementById('body').value   = '';
    document.getElementById('char-hint').textContent = '';
    flash('Entry published successfully.', 'success');
    loadComments();
  } catch (e) {
    flash('Network error. Please try again.');
  } finally {
    btn.disabled = false;
    label.textContent = 'Publish Entry';
    spinner.style.display = 'none';
  }
}

/* ── Like Toggle ─────────────────────────────────────── */
async function toggleLike(id, btn) {
  const isLiked = liked.has(id);
  const action  = isLiked ? 'unlike' : 'like';

  try {
    const res  = await fetch(`/api/comments/${id}/like`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action })
    });
    const data = await res.json();
    if (!res.ok) return;

    if (isLiked) { liked.delete(id); btn.classList.remove('liked'); }
    else         { liked.add(id);    btn.classList.add('liked'); }

    btn.querySelector('.like-count').textContent = data.likes;
  } catch (_) {}
}

/* ── Delete Comment ──────────────────────────────────── */
async function deleteComment(id) {
  if (!confirm('Remove this entry permanently?')) return;

  try {
    const res = await fetch(`/api/comments/${id}`, { method: 'DELETE' });
    if (res.ok) {
      const el = document.getElementById(`comment-${id}`);
      if (el) { el.style.opacity = '0'; el.style.transform = 'translateX(-8px)';
                el.style.transition = 'all .25s';
                setTimeout(() => { el.remove(); loadComments(); }, 250); }
    }
  } catch (_) {}
}

/* ── Char Counter ────────────────────────────────────── */
document.getElementById('body').addEventListener('input', function() {
  const left = 2000 - this.value.length;
  const hint = document.getElementById('char-hint');
  hint.textContent = left < 200 ? `${left} characters remaining` : '';
  hint.style.color = left < 50 ? '#b94040' : '#888';
});

/* ── Enter to Submit (Ctrl/Cmd+Enter) ────────────────── */
document.getElementById('body').addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') submitComment();
});

/* ── Init ────────────────────────────────────────────── */
loadComments();
</script>
</body>
</html>"""


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/api/comments", methods=["GET"])
def get_comments():
    try:
        with get_db() as conn:
            rows = conn.execute(
                "SELECT id, author, body, likes, created_at FROM comments ORDER BY id DESC"
            ).fetchall()
        return jsonify([dict(r) for r in rows])
    except Exception:
        logger.exception("GET /api/comments failed")
        return jsonify({"error": "Could not retrieve comments."}), 500


@app.route("/api/comments", methods=["POST"])
def post_comment():
    try:
        data   = request.get_json(silent=True) or {}
        author = str(data.get("author", "")).strip()
        body   = str(data.get("body", "")).strip()

        valid, msg = validate_comment(author, body)
        if not valid:
            return jsonify({"error": msg}), 400

        # Escape before storage for defence-in-depth
        safe_author = html.escape(author)
        safe_body   = html.escape(body)
        now         = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        with get_db() as conn:
            cur = conn.execute(
                "INSERT INTO comments (author, body, likes, created_at) VALUES (?, ?, 0, ?)",
                (safe_author, safe_body, now)        # ← parameterized query
            )
            conn.commit()
            new_id = cur.lastrowid

        return jsonify({"id": new_id, "author": safe_author,
                        "body": safe_body, "likes": 0, "created_at": now}), 201

    except Exception:
        logger.exception("POST /api/comments failed")
        return jsonify({"error": "Could not save comment."}), 500


@app.route("/api/comments/<int:comment_id>/like", methods=["POST"])
def like_comment(comment_id):
    try:
        data   = request.get_json(silent=True) or {}
        action = data.get("action", "like")

        if action not in ("like", "unlike"):          # strict whitelist
            return jsonify({"error": "Invalid action."}), 400

        delta = 1 if action == "like" else -1

        with get_db() as conn:
            conn.execute(
                "UPDATE comments SET likes = MAX(0, likes + ?) WHERE id = ?",
                (delta, comment_id)                   # ← parameterized query
            )
            conn.commit()
            row = conn.execute(
                "SELECT likes FROM comments WHERE id = ?", (comment_id,)
            ).fetchone()

        if not row:
            return jsonify({"error": "Comment not found."}), 404

        return jsonify({"likes": row["likes"]})

    except Exception:
        logger.exception("LIKE /api/comments/%s failed", comment_id)
        return jsonify({"error": "Could not update like."}), 500


@app.route("/api/comments/<int:comment_id>", methods=["DELETE"])
def delete_comment(comment_id):
    try:
        with get_db() as conn:
            result = conn.execute(
                "DELETE FROM comments WHERE id = ?", (comment_id,)  # ← parameterized
            )
            conn.commit()

        if result.rowcount == 0:
            return jsonify({"error": "Comment not found."}), 404

        return jsonify({"deleted": True})

    except Exception:
        logger.exception("DELETE /api/comments/%s failed", comment_id)
        return jsonify({"error": "Could not delete comment."}), 500


# ─── Error Handlers (no stack traces to users) ────────────────────────────────

@app.errorhandler(400)
def bad_request(_):
    return jsonify({"error": "Bad request."}), 400

@app.errorhandler(404)
def not_found(_):
    return jsonify({"error": "Not found."}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"error": "Method not allowed."}), 405

@app.errorhandler(500)
def server_error(_):
    return jsonify({"error": "Internal server error."}), 500


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)   # NEVER debug=True