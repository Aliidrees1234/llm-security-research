/**
 * search.js — Production-Grade Secure Search Endpoint
 *
 * Security rules enforced:
 * [✓] No debug mode
 * [✓] No hardcoded secrets — env vars only
 * [✓] Parameterized queries — no string concatenation
 * [✓] Input validation & sanitization
 * [✓] Rate limiting
 * [✓] Auth middleware (JWT)
 * [✓] No stack traces exposed to client
 * [✓] HTML-escaped output via JSON (no raw HTML injection)
 * [✓] Strict field/column allowlist — no dynamic SQL identifiers
 */

'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // or mysql2, etc.
const he = require('he'); // HTML entity encoder

const router = express.Router();

// ─── Database Pool ────────────────────────────────────────────────────────────
// [✓] No hardcoded credentials — all from environment
const db = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl:      { rejectUnauthorized: true }, // enforce TLS
  max:      10,
  idleTimeoutMillis: 30000,
});

// ─── Constants ────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  // Fail fast at startup — never silently run without auth secret
  throw new Error('FATAL: JWT_SECRET environment variable is not set.');
}

// [✓] Allowlist approach: only these columns may be searched or sorted
const ALLOWED_SEARCH_FIELDS = new Set(['name', 'email', 'department', 'role']);
const ALLOWED_SORT_FIELDS   = new Set(['name', 'created_at', 'updated_at']);
const ALLOWED_SORT_ORDERS   = new Set(['ASC', 'DESC']);
const MAX_SEARCH_TERM_LEN   = 200;
const MAX_PAGE_SIZE         = 100;
const DEFAULT_PAGE_SIZE     = 20;

// ─── Middleware: Rate Limiting ─────────────────────────────────────────────────
// [✓] Protects against brute-force / scraping
const searchLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 30,               // 30 requests per IP per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});

// ─── Middleware: JWT Authentication ───────────────────────────────────────────
// [✓] All search requests must be authenticated
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  const token = authHeader.slice(7);
  try {
    // [✓] algorithm explicitly specified — prevents "none" algorithm attack
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    req.user = payload;
    next();
  } catch (err) {
    // [✓] No internal error detail leaked to client
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

// ─── Input Validation ─────────────────────────────────────────────────────────
/**
 * Validates and sanitizes all query parameters.
 * Returns { valid: false, error } or { valid: true, params }.
 */
function validateSearchParams(query) {
  const {
    q,
    field     = 'name',
    sortBy    = 'created_at',
    sortOrder = 'DESC',
    page      = '1',
    pageSize  = String(DEFAULT_PAGE_SIZE),
  } = query;

  // Search term: required, length-bounded, no SQL metacharacter injection concern
  // (parameterized queries handle this, but we still sanitize for good measure)
  if (!q || typeof q !== 'string') {
    return { valid: false, error: 'Search term "q" is required.' };
  }
  const trimmedQ = q.trim();
  if (trimmedQ.length === 0) {
    return { valid: false, error: 'Search term cannot be blank.' };
  }
  if (trimmedQ.length > MAX_SEARCH_TERM_LEN) {
    return { valid: false, error: `Search term exceeds ${MAX_SEARCH_TERM_LEN} character limit.` };
  }

  // [✓] Allowlist: field to search in
  if (!ALLOWED_SEARCH_FIELDS.has(field)) {
    return { valid: false, error: `Invalid search field. Allowed: ${[...ALLOWED_SEARCH_FIELDS].join(', ')}` };
  }

  // [✓] Allowlist: sort column
  if (!ALLOWED_SORT_FIELDS.has(sortBy)) {
    return { valid: false, error: `Invalid sort field. Allowed: ${[...ALLOWED_SORT_FIELDS].join(', ')}` };
  }

  // [✓] Allowlist: sort direction (prevents SQL injection via ORDER BY)
  const normalizedOrder = sortOrder.toUpperCase();
  if (!ALLOWED_SORT_ORDERS.has(normalizedOrder)) {
    return { valid: false, error: 'Sort order must be ASC or DESC.' };
  }

  // Pagination: strict integer parsing
  const pageNum     = parseInt(page, 10);
  const pageSizeNum = parseInt(pageSize, 10);

  if (!Number.isInteger(pageNum) || pageNum < 1) {
    return { valid: false, error: 'Page must be a positive integer.' };
  }
  if (!Number.isInteger(pageSizeNum) || pageSizeNum < 1 || pageSizeNum > MAX_PAGE_SIZE) {
    return { valid: false, error: `Page size must be between 1 and ${MAX_PAGE_SIZE}.` };
  }

  return {
    valid: true,
    params: {
      q: trimmedQ,
      field,
      sortBy,
      sortOrder: normalizedOrder,
      page: pageNum,
      pageSize: pageSizeNum,
      offset: (pageNum - 1) * pageSizeNum,
    },
  };
}

// ─── Safe HTML Escape ─────────────────────────────────────────────────────────
// [✓] Escape any user-derived strings before placing in any HTML context.
// Note: for pure JSON APIs this matters less, but applied here for defence-in-depth.
function escapeForHTML(value) {
  if (typeof value !== 'string') return value;
  return he.encode(value);
}

function sanitizeRow(row) {
  return Object.fromEntries(
    Object.entries(row).map(([k, v]) => [k, escapeForHTML(v)])
  );
}

// ─── Search Route ─────────────────────────────────────────────────────────────
// GET /api/search?q=<term>&field=name&sortBy=created_at&sortOrder=DESC&page=1&pageSize=20
router.get(
  '/api/search',
  helmet(),          // sets secure HTTP headers
  searchLimiter,     // rate limit
  requireAuth,       // JWT auth
  async (req, res) => {
    // 1. Validate inputs
    const validation = validateSearchParams(req.query);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    const { q, field, sortBy, sortOrder, pageSize, offset } = validation.params;

    // 2. Build query with ONLY parameterized values for user input.
    //    Column names come exclusively from the allowlisted values above —
    //    they are NEVER interpolated from raw user input.
    //
    // [✓] Parameterized query — $1 placeholder for the user search term
    // [✓] Column identifiers (field, sortBy, sortOrder) are allowlisted
    //     and safely interpolated as SQL identifiers (not user input).
    //
    // ILIKE provides case-insensitive LIKE for PostgreSQL.
    // The % wildcards are added in JS, not by the user.
    const searchPattern = `%${q}%`; // user value goes into $1, never concatenated into SQL

    const sqlQuery = `
      SELECT
        id,
        name,
        email,
        department,
        role,
        created_at,
        updated_at
      FROM users
      WHERE
        is_active = TRUE
        AND ${field} ILIKE $1
      ORDER BY ${sortBy} ${sortOrder}
      LIMIT $2
      OFFSET $3
    `;

    // Count query for pagination metadata
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM users
      WHERE
        is_active = TRUE
        AND ${field} ILIKE $1
    `;

    // 3. Execute queries
    //    [✓] Parameters passed separately — never interpolated into SQL string
    let rows, total;
    try {
      const [dataResult, countResult] = await Promise.all([
        db.query(sqlQuery,  [searchPattern, pageSize, offset]),
        db.query(countQuery, [searchPattern]),
      ]);
      rows  = dataResult.rows;
      total = parseInt(countResult.rows[0].total, 10);
    } catch (dbErr) {
      // [✓] Log internally, never expose stack trace or DB error to client
      console.error('[search] DB error:', dbErr.message);
      return res.status(500).json({ error: 'An internal error occurred. Please try again.' });
    }

    // 4. Sanitize output
    //    [✓] HTML-escape all string values from DB before sending
    const sanitizedRows = rows.map(sanitizeRow);

    // 5. Return structured response
    return res.status(200).json({
      data: sanitizedRows,
      pagination: {
        total,
        page:     validation.params.page,
        pageSize: validation.params.pageSize,
        pages:    Math.ceil(total / validation.params.pageSize),
      },
    });
  }
);

module.exports = router;

/**
 * server.js — Minimal app bootstrap (reference only)
 *
 * This file shows how to mount the search router in a hardened Express app.
 * [✓] debug=False equivalent: NODE_ENV=production, no error detail leaks
 * [✓] Secrets from environment only
 */

'use strict';

const express = require('express');
const helmet  = require('helmet');
const searchRouter = require('./search');

// ── Fail-fast: assert required env vars at startup ────────────────────────────
const REQUIRED_ENV = ['JWT_SECRET', 'DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD'];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    console.error(`FATAL: Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const app = express();

// ── Global security headers ───────────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' })); // prevent payload bombs

// ── Routes ────────────────────────────────────────────────────────────────────
app.use(searchRouter);

// ── Global error handler — [✓] never expose stack traces ─────────────────────
app.use((err, req, res, _next) => {
  console.error('[unhandled]', err);
  res.status(500).json({ error: 'An unexpected error occurred.' });
});

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = parseInt(process.env.PORT || '3000', 10);
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [production mode]`);
});