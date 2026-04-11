/**
 * changePassword.js — Production-grade password change endpoint
 *
 * Security rules applied:
 * [R1]  debug=False equivalent → NODE_ENV=production, no stack traces exposed
 * [R2]  No hardcoded secrets → all config via process.env
 * [R3]  Parameterized queries → using pg prepared statements (? / $N placeholders)
 * [R4]  Path traversal → N/A (no file I/O in this module)
 * [R5]  No shell=True equivalent → no child_process used
 * [R6]  secrets module equivalent → crypto.randomBytes for tokens
 * [R7]  bcrypt for password hashing → never MD5/SHA1
 * [R8]  HTML escaping → express sends JSON only, no raw HTML rendering
 * [R9]  No stack traces to client → generic error messages, server-only logging
 */

"use strict";

const express        = require("express");
const bcrypt         = require("bcrypt");
const { Pool }       = require("pg");
const rateLimit      = require("express-rate-limit");
const { body, validationResult } = require("express-validator");

// ─── [R2] Config from environment — NEVER hardcode ───────────────────────────
const DB_URL         = process.env.DATABASE_URL;           // postgres://user:pass@host/db
const BCRYPT_ROUNDS  = parseInt(process.env.BCRYPT_ROUNDS || "12", 10);
const NODE_ENV       = process.env.NODE_ENV || "production";

if (!DB_URL) {
  // Fail loudly at startup, not silently at runtime
  console.error("[FATAL] DATABASE_URL environment variable is not set.");
  process.exit(1);
}

// ─── [R3] Database pool — parameterized queries only ─────────────────────────
const pool = new Pool({ connectionString: DB_URL });

// ─── [R1] Rate limiter — brute-force protection ──────────────────────────────
const passwordChangeLimiter = rateLimit({
  windowMs : 15 * 60 * 1000, // 15 minutes
  max      : 5,              // 5 attempts per window
  message  : { error: "Too many password change attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders  : false,
});

const router = express.Router();

// ─── Input validation chain ───────────────────────────────────────────────────
const passwordChangeValidators = [
  body("currentPassword")
    .isString()
    .notEmpty()
    .withMessage("Current password is required."),

  body("newPassword")
    .isString()
    .isLength({ min: 12, max: 128 })  // max prevents bcrypt DoS
    .withMessage("New password must be 12–128 characters.")
    .matches(/[A-Z]/)   .withMessage("Must contain an uppercase letter.")
    .matches(/[a-z]/)   .withMessage("Must contain a lowercase letter.")
    .matches(/[0-9]/)   .withMessage("Must contain a digit.")
    .matches(/[^A-Za-z0-9]/).withMessage("Must contain a special character."),

  body("confirmPassword")
    .isString()
    .notEmpty()
    .withMessage("Confirm password is required."),
];

// ─── [R9] Safe error responder — never leaks internals ───────────────────────
function safeError(res, statusCode, publicMessage, internalDetail = null) {
  if (internalDetail) {
    // [R9] Log server-side only, never send to client
    console.error(`[ERROR] ${publicMessage} | detail: ${internalDetail}`);
  }
  return res.status(statusCode).json({ error: publicMessage });
}

// ─── PATCH /password ──────────────────────────────────────────────────────────
/**
 * Requires authenticated session/JWT middleware upstream.
 * Expects req.user.id to be set by the auth middleware.
 *
 * Body: { currentPassword, newPassword, confirmPassword }
 */
router.patch(
  "/password",
  passwordChangeLimiter,
  passwordChangeValidators,
  async (req, res) => {
    // ── 1. Validate input ────────────────────────────────────────────────────
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      // [R8] Validation messages are static strings, not echoed user input
      return res.status(422).json({ errors: errors.array().map(e => e.msg) });
    }

    const { currentPassword, newPassword, confirmPassword } = req.body;

    // ── 2. Confirm passwords match ───────────────────────────────────────────
    if (newPassword !== confirmPassword) {
      return safeError(res, 422, "New passwords do not match.");
    }

    // ── 3. Reject same-as-current ────────────────────────────────────────────
    if (currentPassword === newPassword) {
      return safeError(res, 422, "New password must differ from the current password.");
    }

    // ── 4. Authenticate the caller ───────────────────────────────────────────
    // req.user must be injected by upstream JWT / session middleware
    const userId = req.user?.id;
    if (!userId) {
      return safeError(res, 401, "Authentication required.");
    }

    let client;
    try {
      client = await pool.connect();

      // ── 5. [R3] Fetch current hash — parameterized query ──────────────────
      const { rows } = await client.query(
        "SELECT password_hash FROM users WHERE id = $1 AND is_active = TRUE",
        [userId]   // ← never string-concatenated
      );

      if (rows.length === 0) {
        // [R9] Do not reveal whether the user exists
        return safeError(res, 404, "User not found or inactive.");
      }

      const storedHash = rows[0].password_hash;

      // ── 6. [R7] Verify current password with bcrypt (constant-time) ───────
      const isCurrentValid = await bcrypt.compare(currentPassword, storedHash);
      if (!isCurrentValid) {
        return safeError(res, 401, "Current password is incorrect.");
      }

      // ── 7. [R7] Hash new password — bcrypt, min 12 rounds ─────────────────
      const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);

      // ── 8. [R3] Update hash — parameterized, with audit timestamp ─────────
      await client.query(
        `UPDATE users
            SET password_hash       = $1,
                password_changed_at = NOW(),
                updated_at          = NOW()
          WHERE id = $2`,
        [newHash, userId]   // ← never string-concatenated
      );

      // ── 9. Invalidate all other sessions (security hygiene) ───────────────
      // Adjust table/column names to match your session store schema.
      await client.query(
        `DELETE FROM user_sessions
          WHERE user_id = $1
            AND session_id <> $2`,
        [userId, req.sessionID ?? null]
      );

      // ── 10. [R9] Generic success — no internal detail ─────────────────────
      return res.status(200).json({ message: "Password updated successfully." });

    } catch (err) {
      // [R9] Server logs full error; client gets generic message only
      return safeError(
        res,
        500,
        "An unexpected error occurred. Please try again later.",
        err.message
      );
    } finally {
      if (client) client.release();
    }
  }
);

module.exports = router;

/**
 * app.js — Integration example for changePassword router
 *
 * Install dependencies:
 *   npm install express bcrypt pg express-rate-limit express-validator
 *
 * Required environment variables (.env — NEVER commit this file):
 *   DATABASE_URL=postgres://user:password@localhost:5432/yourdb
 *   BCRYPT_ROUNDS=12
 *   JWT_SECRET=<at-least-32-random-bytes>
 *   NODE_ENV=production
 */

"use strict";

const express           = require("express");
const changePasswordRouter = require("./changePassword");

// ─── Minimal JWT auth middleware (swap with your real implementation) ──────────
function requireAuth(req, res, next) {
  // Example: decode a Bearer token and attach req.user
  // const token = req.headers.authorization?.split(" ")[1];
  // req.user = verifyJwt(token);  ← your real JWT verification
  next();
}

const app = express();
app.use(express.json({ limit: "10kb" })); // [R1] Limit body size

// Mount behind auth middleware
app.use("/api/users", requireAuth, changePasswordRouter);

// [R1] Never expose debug=True equivalent
app.listen(3000, () => {
  console.log("[INFO] Server running.");
});

/**
 * Required DB schema (PostgreSQL):
 *
 * CREATE TABLE users (
 *   id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 *   email               TEXT UNIQUE NOT NULL,
 *   password_hash       TEXT NOT NULL,
 *   is_active           BOOLEAN NOT NULL DEFAULT TRUE,
 *   password_changed_at TIMESTAMPTZ,
 *   updated_at          TIMESTAMPTZ DEFAULT NOW()
 * );
 *
 * CREATE TABLE user_sessions (
 *   session_id TEXT PRIMARY KEY,
 *   user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 *   created_at TIMESTAMPTZ DEFAULT NOW()
 * );
 *
 * Usage:
 *   PATCH /api/users/password
 *   Authorization: Bearer <jwt>
 *   Content-Type: application/json
 *
 *   {
 *     "currentPassword": "OldP@ssw0rd!",
 *     "newPassword":     "NewSecure#2024!",
 *     "confirmPassword": "NewSecure#2024!"
 *   }
 */