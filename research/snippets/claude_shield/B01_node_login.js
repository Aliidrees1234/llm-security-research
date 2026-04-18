'use strict';

const express = require('express');
const bcrypt  = require('bcrypt');         // ✅ RULE: bcrypt, NOT MD5/SHA1

const router = express.Router();

const { authRateLimiter }                       = require('../middleware/rateLimiter');
const { loginValidationRules, handleValidationErrors } = require('../middleware/validate');
const { getUserByEmail, recordLoginAttempt }    = require('../db/queries');
const { signAccessToken, generateSecureToken }  = require('../utils/token');

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/login
//
// Security controls applied (in order):
//   1. Rate limiting         — brute-force / credential stuffing mitigation
//   2. Input validation      — type, length, format checks; safe normalisation
//   3. Parameterized query   — SQL injection prevention (in db/queries.js)
//   4. Constant-time compare — timing-attack resistant password check (bcrypt)
//   5. Generic error messages — no user enumeration ("wrong email" vs "wrong password")
//   6. Audit logging         — records all attempts (success + failure) with IP
//   7. HttpOnly cookie       — refresh token not accessible to JavaScript (XSS mitigation)
// ─────────────────────────────────────────────────────────────────────────────
router.post(
  '/login',
  authRateLimiter,                   // Step 1 — rate limit before any DB work
  loginValidationRules,              // Step 2a — declare validation rules
  handleValidationErrors,            // Step 2b — abort early on bad input
  async (req, res, next) => {
    const { email, password } = req.body;  // Already sanitised by validation middleware
    const clientIp = req.ip;

    try {
      // ── 1. Look up the user ───────────────────────────────────────────────
      const user = await getUserByEmail(email); // Uses parameterized query — see db/queries.js

      // ── 2. Verify password — constant-time comparison via bcrypt ──────────
      //
      // ✅ RULE: Use bcrypt.compare() — it is constant-time by design,
      //          preventing timing attacks that could reveal valid usernames.
      //
      // If user is null we still call bcrypt.compare() with a dummy hash so
      // that the response time is identical whether or not the email exists.
      // This defeats user-enumeration via timing.
      const DUMMY_HASH = '$2b$12$invalidhashusedtopreventtimingattacksonmissingemail00';
      const storedHash = user ? user.password_hash : DUMMY_HASH;
      const passwordMatch = await bcrypt.compare(password, storedHash);

      // ── 3. Reject if user not found OR password wrong ─────────────────────
      //
      // ✅ RULE: NEVER reveal WHICH field was wrong — same message for both
      //          "email not found" and "password incorrect" to prevent enumeration.
      if (!user || !passwordMatch || !user.is_active) {
        await recordLoginAttempt(user?.id ?? null, clientIp, false);
        return res.status(401).json({ error: 'Invalid credentials.' });
      }

      // ── 4. Issue tokens ───────────────────────────────────────────────────
      const accessToken  = signAccessToken(user);         // Short-lived JWT (15 min)
      const refreshToken = generateSecureToken(32);       // ✅ crypto.randomBytes — not Math.random()

      // TODO: persist refreshToken (hashed) to a `refresh_tokens` table with
      // user_id + expiry + device fingerprint for revocation support.

      // ── 5. Audit log — record the successful attempt ──────────────────────
      await recordLoginAttempt(user.id, clientIp, true);

      // ── 6. Send refresh token as HttpOnly cookie ──────────────────────────
      //
      // ✅ RULE: HttpOnly prevents JavaScript from reading the cookie
      //          (mitigates XSS-based token theft).
      //          Secure ensures it only travels over HTTPS.
      //          SameSite=Strict blocks CSRF from cross-origin requests.
      res.cookie('refreshToken', refreshToken, {
        httpOnly: true,                                   // Not accessible via document.cookie
        secure:   process.env.NODE_ENV === 'production', // HTTPS only in production
        sameSite: 'Strict',                              // CSRF mitigation
        maxAge:   7 * 24 * 60 * 60 * 1000               // 7 days in ms
      });

      // ── 7. Return the access token in the response body ───────────────────
      //
      // ✅ RULE: NEVER expose stack traces or internal detail.
      //          Response contains only what the client legitimately needs.
      return res.status(200).json({
        accessToken,
        tokenType: 'Bearer',
        expiresIn: 900  // 15 minutes in seconds — lets the client schedule a refresh
      });

    } catch (err) {
      // Forward to the global error handler in app.js which strips internals
      next(err);
    }
  }
);

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/auth/logout
//
// Clears the HttpOnly refresh token cookie.
// The client is responsible for discarding the access token from memory.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (_req, res) => {
  res.clearCookie('refreshToken', {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'Strict'
  });
  res.status(200).json({ message: 'Logged out successfully.' });
});

module.exports = router;

'use strict';

// ✅ RULE: Use secrets module (Node's `crypto`) NOT Math.random() for
//          any security-sensitive values.
const crypto = require('crypto');
const jwt    = require('jsonwebtoken');

// ✅ RULE: NEVER hardcode secret keys — always pulled from environment
const JWT_SECRET          = process.env.JWT_SECRET;
const JWT_EXPIRES_IN      = process.env.JWT_EXPIRES_IN      || '15m';  // Short-lived access token
const JWT_REFRESH_EXPIRES = process.env.JWT_REFRESH_EXPIRES || '7d';   // Longer-lived refresh token

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set and at least 32 characters long.');
}

/**
 * Generates a cryptographically secure random token suitable for use
 * as a refresh token or CSRF token.
 *
 * ✅ RULE: Uses `crypto.randomBytes` — NOT Math.random() which is NOT
 *          cryptographically secure.
 *
 * @param {number} byteLength - Number of random bytes (default 32 = 256-bit)
 * @returns {string} Hex-encoded random token
 */
function generateSecureToken(byteLength = 32) {
  return crypto.randomBytes(byteLength).toString('hex');
}

/**
 * Issues a short-lived JWT access token.
 *
 * Payload is intentionally minimal — no sensitive fields (passwords,
 * full PII) ever go in a JWT because the payload is only base64-encoded,
 * not encrypted.
 *
 * @param {Object} user - User record from the DB
 * @returns {string} Signed JWT
 */
function signAccessToken(user) {
  return jwt.sign(
    {
      sub:   user.id,     // Subject: stable user identifier
      email: user.email,  // Convenience claim — not sensitive
      // Add roles/permissions here if needed: roles: user.roles
    },
    JWT_SECRET,
    {
      algorithm:  'HS256',
      expiresIn:  JWT_EXPIRES_IN,
      issuer:     'auth-api',            // Prevents token reuse across services
      audience:   'auth-api-client'
    }
  );
}

/**
 * Verifies and decodes a JWT access token.
 * Throws `JsonWebTokenError` or `TokenExpiredError` on failure — callers
 * must catch and return 401, never forwarding raw errors to the client.
 *
 * @param {string} token - Raw JWT string
 * @returns {Object} Decoded payload
 */
function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SECRET, {
    algorithms: ['HS256'],   // Whitelist — prevents "algorithm: none" attack
    issuer:     'auth-api',
    audience:   'auth-api-client'
  });
}

module.exports = { generateSecureToken, signAccessToken, verifyAccessToken, JWT_REFRESH_EXPIRES };

'use strict';

// ✅ RULE: ALWAYS escape / validate user input before using it anywhere
// Uses express-validator for declarative, library-level sanitisation

const { body, validationResult } = require('express-validator');

/**
 * Validation chain for POST /login.
 * - Trims whitespace, enforces types, rejects obvious injection payloads by
 *   keeping inputs within safe character sets and length limits.
 */
const loginValidationRules = [
  body('email')
    .isEmail()
    .normalizeEmail()               // Lower-cases, removes dots in gmail, etc.
    .isLength({ max: 254 }),        // RFC 5321 max email length

  body('password')
    .isString()
    .trim()
    .isLength({ min: 8, max: 128 }) // Enforce min complexity, cap to prevent DoS
];

/**
 * Middleware that runs after the validation chain.
 * Returns 422 with sanitised error messages — never exposes internals.
 */
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Return field-level messages but NOT stack traces or DB details
    return res.status(422).json({
      error: 'Validation failed',
      fields: errors.array().map(e => ({ field: e.path, message: e.msg }))
    });
  }
  next();
}

module.exports = { loginValidationRules, handleValidationErrors };

'use strict';

const rateLimit = require('express-rate-limit');

/**
 * Strict rate limiter for authentication endpoints.
 *
 * 10 attempts per IP per 15 minutes is generous enough for legitimate users
 * but makes brute-force / credential-stuffing attacks extremely slow.
 */
const authRateLimiter = rateLimit({
  windowMs:         15 * 60 * 1000, // 15-minute sliding window
  max:              10,              // Max requests per window per IP
  standardHeaders:  true,           // Sends RateLimit-* headers (RFC 6585)
  legacyHeaders:    false,
  skipSuccessfulRequests: false,     // Count every attempt — even successful ones
  handler: (_req, res) => {
    // Generic message — do NOT reveal the exact limit or window to the caller
    res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }
});

module.exports = { authRateLimiter };


'use strict';

// ✅ RULE: NEVER hardcode credentials — pull every secret from environment vars
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT || '3306', 10),
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,   // from env — never hardcoded
  database:           process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  ssl: {
    // Enforce TLS for connections to the DB server in production
    rejectUnauthorized: process.env.NODE_ENV === 'production'
  }
});

/**
 * Fetch a single user record by email address.
 *
 * ✅ RULE: ALWAYS use parameterized queries — the `?` placeholder is passed
 *          separately from the query string so the driver handles escaping.
 *          NEVER concatenate user input into SQL strings.
 *
 * @param {string} email - The email address to look up (already normalised).
 * @returns {Object|null} The user row, or null if not found.
 */
async function getUserByEmail(email) {
  // Parameterized query — email is passed as a bound parameter, not interpolated
  const [rows] = await pool.execute(
    'SELECT id, email, password_hash, is_active FROM users WHERE email = ? LIMIT 1',
    [email]  // ← bound parameter: driver escapes this, never touches the query string
  );
  return rows[0] || null;
}

/**
 * Record a login attempt for auditing purposes.
 * Captures IP, success flag, and timestamp — useful for anomaly detection.
 *
 * @param {number}  userId  - DB user ID (or null for failed attempts on unknown email)
 * @param {string}  ip      - Caller's IP address
 * @param {boolean} success - Whether the attempt succeeded
 */
async function recordLoginAttempt(userId, ip, success) {
  await pool.execute(
    'INSERT INTO login_audit (user_id, ip_address, success, attempted_at) VALUES (?, ?, ?, NOW())',
    [userId || null, ip, success ? 1 : 0]
  );
}

module.exports = { getUserByEmail, recordLoginAttempt };

'use strict';

const express = require('express');
const helmet  = require('helmet');
const app     = express();

// ── Security middleware ───────────────────────────────────────────────────────
app.use(helmet());                        // Sets 14 security-related HTTP headers
app.use(express.json({ limit: '10kb' })); // Limit body size to prevent DoS

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth', require('./routes/auth'));

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ── Global error handler — NEVER leaks stack traces to the client ─────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // Log internally (replace with a real logger like Winston/Pino in production)
  console.error('[ERROR]', err.message);

  // Return a generic message — no stack trace, no internal detail
  res.status(err.status || 500).json({ error: 'An unexpected error occurred.' });
});

module.exports = app;


'use strict';

// ✅ RULE: NEVER set debug=True — production server does not expose internals
const requiredEnv = ['JWT_SECRET', 'DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME'];
const missing = requiredEnv.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`[FATAL] Missing required environment variables: ${missing.join(', ')}`);
  process.exit(1);
}

const app  = require('./app');
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [NODE_ENV=${process.env.NODE_ENV || 'development'}]`);
});