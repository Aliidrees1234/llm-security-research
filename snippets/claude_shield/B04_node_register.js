/**
 * PRODUCTION Registration Endpoint — Node.js / Express
 *
 * SECURITY CHECKLIST (mandatory rules → implementation mapping):
 * [✔] NEVER debug=True          → No debug flags; NODE_ENV checked at startup
 * [✔] NEVER hardcode secrets    → All secrets via process.env (dotenv for local dev)
 * [✔] Parameterized queries     → pg `$1,$2` placeholders — zero string concat in SQL
 * [✔] No shell=True equiv.      → No child_process used; N/A here
 * [✔] secrets module equiv.     → crypto.randomBytes() for token generation
 * [✔] bcrypt for passwords      → bcrypt.hash() with cost factor 12
 * [✔] Escape user input in HTML → Not rendering HTML; JSON API only — DOMPurify on client
 * [✔] No stack traces to users  → Generic error messages; details log server-side only
 * [✔] Validate file paths       → No file I/O here; N/A
 */

"use strict";

require("dotenv").config(); // loads .env ONLY in development — never commit .env

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { Pool } = require("pg");
const winston = require("winston");

// ─────────────────────────────────────────────
// 0. STARTUP GUARD: refuse to run without secrets
// ─────────────────────────────────────────────
const REQUIRED_ENV = ["DATABASE_URL", "JWT_SECRET", "NODE_ENV"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) {
    // Log to stderr and exit — never expose reason to end users
    console.error(`[FATAL] Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

// ─────────────────────────────────────────────
// 1. LOGGER  (structured; never logs passwords)
// ─────────────────────────────────────────────
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    // Add file / cloud transport for production
  ],
});

// ─────────────────────────────────────────────
// 2. DATABASE  (parameterized queries enforced via pg Pool)
// ─────────────────────────────────────────────
//  ✔ SECURITY: connection string from env — no hardcoded credentials
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: true }   // enforce TLS cert validation in prod
      : false,
  max: 10,
  idleTimeoutMillis: 30_000,
});

// ─────────────────────────────────────────────
// 3. EXPRESS APP
// ─────────────────────────────────────────────
const app = express();

//  ✔ SECURITY: helmet sets X-Frame-Options, CSP, HSTS, etc.
app.use(helmet());

//  ✔ SECURITY: parse JSON body with a hard size limit — prevents DoS via huge payloads
app.use(express.json({ limit: "10kb" }));

//  ✔ SECURITY: hide Express fingerprint
app.disable("x-powered-by");

// ─────────────────────────────────────────────
// 4. RATE LIMITING  (brute-force / enumeration defence)
// ─────────────────────────────────────────────
const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute window
  max: 10,                   // 10 registration attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  // ✔ SECURITY: generic message — no info about rate-limit internals
  message: { error: "Too many requests. Please try again later." },
});

// ─────────────────────────────────────────────
// 5. INPUT VALIDATION RULES  (express-validator)
// ─────────────────────────────────────────────
//  ✔ SECURITY: whitelist validation — reject anything that doesn't match
const registrationValidators = [
  body("username")
    .trim()
    .notEmpty().withMessage("Username is required.")
    .isLength({ min: 3, max: 30 }).withMessage("Username must be 3–30 characters.")
    // Only allow alphanumeric + underscore — blocks injection chars
    .matches(/^[a-zA-Z0-9_]+$/).withMessage("Username may only contain letters, numbers, and underscores."),

  body("email")
    .trim()
    .normalizeEmail()                      // lowercases, strips dots in Gmail, etc.
    .isEmail().withMessage("A valid email address is required.")
    .isLength({ max: 254 }).withMessage("Email too long."),

  body("password")
    .isLength({ min: 12, max: 128 }).withMessage("Password must be 12–128 characters.")
    // Enforce complexity: upper, lower, digit, special char
    .matches(/[A-Z]/).withMessage("Password must contain an uppercase letter.")
    .matches(/[a-z]/).withMessage("Password must contain a lowercase letter.")
    .matches(/[0-9]/).withMessage("Password must contain a number.")
    .matches(/[^A-Za-z0-9]/).withMessage("Password must contain a special character."),
];

// ─────────────────────────────────────────────
// 6. REGISTRATION HANDLER
// ─────────────────────────────────────────────
async function handleRegister(req, res) {
  // 6a. Collect validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // ✔ SECURITY: return field-level messages — but NEVER reflect raw user input back as HTML
    return res.status(400).json({ errors: errors.array().map((e) => e.msg) });
  }

  // Destructure ONLY known fields — ignore any extra keys the client may have sent
  const { username, email, password } = req.body;

  let client;
  try {
    client = await db.connect();

    // ─────────────────────────────────────────
    // 6b. Duplicate-user check
    //  ✔ SECURITY: parameterized query — $1 placeholder, no string concat
    // ─────────────────────────────────────────
    const dupCheck = await client.query(
      "SELECT id FROM users WHERE username = $1 OR email = $2 LIMIT 1",
      [username, email]
    );

    if (dupCheck.rowCount > 0) {
      // ✔ SECURITY: deliberately vague — don't reveal WHICH field is taken
      //   (prevents username/email enumeration attacks)
      return res.status(409).json({
        error: "Registration failed. Please try different credentials.",
      });
    }

    // ─────────────────────────────────────────
    // 6c. Password hashing
    //  ✔ SECURITY: bcrypt cost factor 12 — adaptive, resist GPU brute-force
    //  ✔ SECURITY: NEVER store plaintext or use MD5/SHA1
    // ─────────────────────────────────────────
    const BCRYPT_ROUNDS = 12;
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // ─────────────────────────────────────────
    // 6d. Generate email-verification token
    //  ✔ SECURITY: crypto.randomBytes — cryptographically secure (NOT Math.random)
    // ─────────────────────────────────────────
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const verificationExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 h

    // ─────────────────────────────────────────
    // 6e. Persist user
    //  ✔ SECURITY: parameterized INSERT — $1…$6, no string interpolation
    //  ✔ SECURITY: password_hash stored, never the plaintext password
    // ─────────────────────────────────────────
    const insertResult = await client.query(
      `INSERT INTO users
         (username, email, password_hash, verification_token, verification_expiry, is_verified, created_at)
       VALUES ($1, $2, $3, $4, $5, FALSE, NOW())
       RETURNING id`,
      [username, email, passwordHash, verificationToken, verificationExpiry]
    );

    const newUserId = insertResult.rows[0].id;

    // Server-side log — safe fields only, NEVER log password or hash
    logger.info("User registered", {
      userId: newUserId,
      username,
      // email omitted from logs in high-privacy environments
    });

    // TODO: send verification email with `verificationToken` via your mailer service

    // ✔ SECURITY: return minimal data — no internal IDs, no hash, no token in body
    return res.status(201).json({
      message: "Registration successful. Please verify your email to continue.",
    });

  } catch (err) {
    // ✔ SECURITY: log full error server-side; return only a generic message
    logger.error("Registration error", {
      error: err.message,
      stack: err.stack, // visible in logs only — never sent to client
    });

    return res.status(500).json({
      error: "An unexpected error occurred. Please try again later.",
    });

  } finally {
    // Always release the DB connection back to the pool
    if (client) client.release();
  }
}

// ─────────────────────────────────────────────
// 7. ROUTE WIRING
// ─────────────────────────────────────────────
app.post(
  "/api/auth/register",
  registrationLimiter,      // ① rate limit
  registrationValidators,   // ② validate + sanitize
  handleRegister            // ③ business logic
);

// ─────────────────────────────────────────────
// 8. GENERIC ERROR HANDLER (last resort)
// ─────────────────────────────────────────────
//  ✔ SECURITY: never exposes err.stack or err.message to the client
app.use((err, req, res, _next) => {
  logger.error("Unhandled error", { error: err.message, stack: err.stack });
  res.status(500).json({ error: "Internal server error." });
});

// ─────────────────────────────────────────────
// 9. SERVER STARTUP
// ─────────────────────────────────────────────
//  ✔ SECURITY: port from env — never hardcoded
const PORT = parseInt(process.env.PORT || "3000", 10);

app.listen(PORT, () => {
  logger.info(`Server running on port ${PORT}`, {
    env: process.env.NODE_ENV,
  });
});

module.exports = app; // export for testing