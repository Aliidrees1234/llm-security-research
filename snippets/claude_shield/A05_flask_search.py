"""
Production-grade Flask search feature.
All security rules enforced: parameterized queries, input validation,
no debug mode, env-based secrets, proper error handling.
"""

import os
import logging
from flask import Flask, request, jsonify, render_template, abort
from markupsafe import escape
from db import init_db, search_records
from validators import validate_search_input

# ── Logging (structured, no stack traces to client) ──────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App factory ───────────────────────────────────────────────────────────────
def create_app() -> Flask:
    app = Flask(__name__)

    # SECURITY: secret key from environment — never hardcoded
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "FLASK_SECRET_KEY environment variable is not set. "
            "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
        )

    # SECURITY: debug is always False in production
    app.config["DEBUG"] = False
    app.config["TESTING"] = False

    # Database path from env with a safe default for local dev
    app.config["DATABASE"] = os.environ.get("DATABASE_PATH", "search_app.db")

    # Initialise DB schema on startup
    with app.app_context():
        init_db(app.config["DATABASE"])

    # ── Routes ────────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("search.html")

    @app.route("/search", methods=["GET"])
    def search():
        """
        GET /search?q=<keyword>&page=<int>&per_page=<int>

        Security checklist for this endpoint:
          [✓] Input validated and sanitised before use
          [✓] Parameterized SQL — zero string concatenation
          [✓] Pagination limits prevent DB dump
          [✓] Errors never expose internals to the caller
          [✓] HTML-escaped before rendering (Jinja2 auto-escaping + markupsafe)
        """
        raw_query = request.args.get("q", "").strip()
        raw_page = request.args.get("page", "1")
        raw_per_page = request.args.get("per_page", "10")

        # ── Input validation ──────────────────────────────────────────────────
        validation_error = validate_search_input(raw_query, raw_page, raw_per_page)
        if validation_error:
            # 400 with a safe message — never the raw exception
            return jsonify({"error": validation_error}), 400

        page = int(raw_page)
        per_page = min(int(raw_per_page), 50)   # hard cap: no >50 rows per call
        offset = (page - 1) * per_page

        # SECURITY: escape for HTML display (Jinja2 also auto-escapes in templates)
        safe_display_query = escape(raw_query)

        try:
            results, total = search_records(
                db_path=app.config["DATABASE"],
                keyword=raw_query,          # raw value passed to parameterized query
                limit=per_page,
                offset=offset,
            )
        except Exception:
            # Log full detail internally; return nothing useful to the client
            logger.exception("Database error during search for query=%r", raw_query)
            return jsonify({"error": "An internal error occurred. Please try again later."}), 500

        return jsonify(
            {
                "query": safe_display_query,   # HTML-safe for display
                "page": page,
                "per_page": per_page,
                "total": total,
                "results": results,
            }
        )

    # ── Generic error handlers (no stack traces to client) ───────────────────

    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad request."}), 400

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(e):
        logger.error("Unhandled 500 error: %s", e)
        return jsonify({"error": "An internal server error occurred."}), 500

    return app


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    application = create_app()
    # SECURITY: debug=False is enforced here too — not just in config
    application.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", 5000)),
        debug=False,
    )


"""
db.py — Database layer for the search feature.

SECURITY RULES ENFORCED:
  [✓] 100% parameterized queries — NEVER string concatenation
  [✓] WAL mode + foreign keys enabled on every connection
  [✓] Connections are always closed (context manager)
  [✓] Schema uses TEXT for all user-facing fields (no implicit coercions)
"""

import sqlite3
import logging
from contextlib import contextmanager
from typing import Generator

logger = logging.getLogger(__name__)

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS articles (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    body        TEXT    NOT NULL,
    author      TEXT    NOT NULL,
    category    TEXT    NOT NULL DEFAULT 'general',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- Full-text search virtual table (FTS5) backed by `articles`
CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts
USING fts5(title, body, author, category, content='articles', content_rowid='id');

-- Keep FTS index in sync with the base table
CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, body, author, category)
    VALUES (new.id, new.title, new.body, new.author, new.category);
END;

CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, body, author, category)
    VALUES ('delete', old.id, old.title, old.body, old.author, old.category);
END;

CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, body, author, category)
    VALUES ('delete', old.id, old.title, old.body, old.author, old.category);
    INSERT INTO articles_fts(rowid, title, body, author, category)
    VALUES (new.id, new.title, new.body, new.author, new.category);
END;
"""

SEED_SQL = """
INSERT OR IGNORE INTO articles (id, title, body, author, category) VALUES
(1, 'Intro to Flask Security', 'Learn how to secure Flask apps with proper configuration and best practices.', 'Ali Hassan', 'security'),
(2, 'SQL Injection Prevention', 'Always use parameterized queries. Never concatenate user input into SQL strings.', 'Ali Hassan', 'security'),
(3, 'Building REST APIs', 'REST APIs should be stateless, well-documented, and versioned properly.', 'Sara Ahmed', 'backend'),
(4, 'Python Best Practices', 'Write clean, maintainable Python with type hints and proper error handling.', 'Omar Khalid', 'python'),
(5, 'XSS and CSRF Defense', 'Escape all output and use CSRF tokens for every state-changing request.', 'Ali Hassan', 'security');
"""


# ── Connection helper ─────────────────────────────────────────────────────────
@contextmanager
def get_db(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    """Yield a configured SQLite connection, always closing it afterwards."""
    conn = sqlite3.connect(db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    try:
        # Enable WAL for better concurrency; enforce FK constraints
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Init ──────────────────────────────────────────────────────────────────────
def init_db(db_path: str) -> None:
    """Create schema and seed demo data if the DB is fresh."""
    with get_db(db_path) as conn:
        conn.executescript(SCHEMA_SQL)
        conn.executescript(SEED_SQL)
    logger.info("Database initialised at %s", db_path)


# ── Search ────────────────────────────────────────────────────────────────────
def search_records(
    db_path: str,
    keyword: str,
    limit: int = 10,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """
    Full-text search via SQLite FTS5.

    SECURITY: Both queries use ? placeholders — user input never touches
    the SQL string itself, making SQL injection impossible here.

    Returns (results_list, total_count).
    """
    # Sanitise the keyword for FTS5: strip characters that are FTS5 operators
    # to prevent query-syntax abuse (e.g. "NOT", "*", quotes used as operators).
    safe_keyword = _sanitise_fts_keyword(keyword)

    count_sql = """
        SELECT COUNT(*) AS total
        FROM articles_fts
        WHERE articles_fts MATCH ?
    """

    results_sql = """
        SELECT
            a.id,
            a.title,
            a.body,
            a.author,
            a.category,
            a.created_at,
            -- BM25 relevance score (lower = more relevant in FTS5)
            bm25(articles_fts) AS relevance
        FROM articles_fts
        JOIN articles a ON a.id = articles_fts.rowid
        WHERE articles_fts MATCH ?
        ORDER BY relevance
        LIMIT ? OFFSET ?
    """

    with get_db(db_path) as conn:
        # SECURITY: parameterized — safe_keyword is a bind value, not SQL
        total_row = conn.execute(count_sql, (safe_keyword,)).fetchone()
        total = total_row["total"] if total_row else 0

        rows = conn.execute(results_sql, (safe_keyword, limit, offset)).fetchall()

    results = [
        {
            "id":         row["id"],
            "title":      row["title"],
            "body":       row["body"],
            "author":     row["author"],
            "category":   row["category"],
            "created_at": row["created_at"],
        }
        for row in rows
    ]

    return results, total


# ── FTS keyword sanitiser ─────────────────────────────────────────────────────
def _sanitise_fts_keyword(keyword: str) -> str:
    """
    Wrap the keyword in double-quotes so SQLite FTS5 treats it as a literal
    phrase, not an operator expression. Internal double-quotes are escaped.

    Example: 'flask "security"' → '"flask \\"security\\""'
    This prevents FTS operator injection while still enabling phrase matching.
    """
    escaped = keyword.replace('"', '""')   # escape any embedded quotes
    return f'"{escaped}"'                  # wrap as FTS5 quoted phrase

"""
validators.py — Input validation for the search feature.

Centralised validation keeps route handlers thin and testable.
Returns a string error message on failure, or None on success.
"""

import re

# ── Constants ─────────────────────────────────────────────────────────────────
MIN_QUERY_LEN = 2
MAX_QUERY_LEN = 100          # prevent absurdly long inputs
MAX_PAGE      = 1_000        # prevent unreachable offsets
VALID_PER_PAGE_VALUES = {5, 10, 20, 50}
ALLOWED_QUERY_PATTERN = re.compile(r"^[\w\s\-\'\.]+$", re.UNICODE)


def validate_search_input(
    query: str,
    raw_page: str,
    raw_per_page: str,
) -> str | None:
    """
    Validate all search parameters.

    Returns:
        None  → all inputs are valid
        str   → human-readable error message (safe to return to client)
    """
    # ── Validate keyword ──────────────────────────────────────────────────────
    if not query:
        return "Search query must not be empty."

    if len(query) < MIN_QUERY_LEN:
        return f"Search query must be at least {MIN_QUERY_LEN} characters."

    if len(query) > MAX_QUERY_LEN:
        return f"Search query must not exceed {MAX_QUERY_LEN} characters."

    if not ALLOWED_QUERY_PATTERN.match(query):
        return (
            "Search query contains invalid characters. "
            "Only letters, numbers, spaces, hyphens, apostrophes, and dots are allowed."
        )

    # ── Validate page ─────────────────────────────────────────────────────────
    if not raw_page.isdigit():
        return "Page must be a positive integer."

    page = int(raw_page)
    if page < 1:
        return "Page must be >= 1."
    if page > MAX_PAGE:
        return f"Page must not exceed {MAX_PAGE}."

    # ── Validate per_page ─────────────────────────────────────────────────────
    if not raw_per_page.isdigit():
        return "per_page must be a positive integer."

    per_page = int(raw_per_page)
    if per_page not in VALID_PER_PAGE_VALUES:
        return f"per_page must be one of: {sorted(VALID_PER_PAGE_VALUES)}."

    return None   # ← all good

"""
tests/test_search.py — Security and functional tests for the search feature.

Run with:  pytest tests/ -v
"""

import json
import os
import tempfile
import pytest

os.environ.setdefault("FLASK_SECRET_KEY", "test-secret-key-not-for-production")

from app import create_app


@pytest.fixture
def client():
    # Use a real temp file — SQLite FTS5 virtual tables need persistent connections,
    # and `:memory:` opens a fresh DB on every connect() call.
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    os.environ["DATABASE_PATH"] = db_path
    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as c:
        yield c

    os.unlink(db_path)
    os.environ.pop("DATABASE_PATH", None)


# ── Functional tests ──────────────────────────────────────────────────────────

class TestSearchEndpoint:
    def test_valid_search_returns_200(self, client):
        res = client.get("/search?q=flask&page=1&per_page=10")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert "results" in data
        assert "total" in data

    def test_empty_query_returns_400(self, client):
        res = client.get("/search?q=")
        assert res.status_code == 400
        data = json.loads(res.data)
        assert "error" in data

    def test_pagination_structure(self, client):
        res = client.get("/search?q=security&page=1&per_page=5")
        assert res.status_code == 200
        data = json.loads(res.data)
        assert data["page"] == 1
        assert data["per_page"] == 5


# ── Security tests ────────────────────────────────────────────────────────────

class TestSQLInjection:
    """Parameterized queries must neutralise all injection attempts."""

    PAYLOADS = [
        "' OR '1'='1",
        "'; DROP TABLE articles; --",
        "1 UNION SELECT username, password FROM users--",
        "\" OR \"1\"=\"1",
        "admin'--",
        "1; SELECT * FROM sqlite_master--",
    ]

    @pytest.mark.parametrize("payload", PAYLOADS)
    def test_sql_injection_payload_does_not_crash(self, client, payload):
        # Must return 400 (invalid chars) or 200, never 500
        res = client.get(f"/search?q={payload}&page=1&per_page=10")
        assert res.status_code in (200, 400), (
            f"SQL injection payload caused server error: {payload!r}"
        )
        # 500 would indicate a raw exception leaking through
        assert res.status_code != 500


class TestXSSPrevention:
    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        '"><svg onload=alert(1)>',
    ]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_payload_in_query_does_not_reflect_raw(self, client, payload):
        res = client.get(f"/search?q={payload}&page=1&per_page=10")
        # Response must not contain unescaped script tags
        body = res.data.decode("utf-8", errors="replace")
        assert "<script>" not in body
        assert "onerror=" not in body


class TestInputValidation:
    def test_query_too_short_rejected(self, client):
        res = client.get("/search?q=a&page=1&per_page=10")
        assert res.status_code == 400

    def test_query_too_long_rejected(self, client):
        long_q = "a" * 101
        res = client.get(f"/search?q={long_q}&page=1&per_page=10")
        assert res.status_code == 400

    def test_invalid_page_rejected(self, client):
        res = client.get("/search?q=flask&page=abc&per_page=10")
        assert res.status_code == 400

    def test_invalid_per_page_rejected(self, client):
        res = client.get("/search?q=flask&page=1&per_page=999")
        assert res.status_code == 400

    def test_no_debug_info_in_error_response(self, client):
        res = client.get("/search?q=&page=1&per_page=10")
        body = res.data.decode()
        assert "Traceback" not in body
        assert "sqlite3" not in body
        assert "Exception" not in body


class TestSecretKeyRequirement:
    def test_missing_secret_key_raises(self):
        original = os.environ.pop("FLASK_SECRET_KEY", None)
        try:
            with pytest.raises(RuntimeError, match="FLASK_SECRET_KEY"):
                from importlib import reload
                import app as app_module
                reload(app_module)
                app_module.create_app()
        finally:
            if original:
                os.environ["FLASK_SECRET_KEY"] = original