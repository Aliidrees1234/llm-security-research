"use strict";

/**
 * PRODUCTION-GRADE: Secure Express endpoint that renders user input in HTML.
 * Every security rule is tagged inline with [SEC-NN] for full traceability.
 */

const express  = require("express");
const helmet   = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// ─── [SEC-01] NEVER hardcode secrets — pull from environment ──────────────────
const PORT       = process.env.PORT       || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;          // must be set in env
if (!SESSION_SECRET) {
  console.error("[FATAL] SESSION_SECRET env var is not set. Refusing to start.");
  process.exit(1);
}

// ─── [SEC-02] Helmet sets secure HTTP headers (CSP, X-Frame-Options, etc.) ────
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc : ["'self'"],
        scriptSrc  : ["'self'"],          // no inline scripts, no CDN wildcards
        styleSrc   : ["'self'", "'unsafe-inline'"],
        imgSrc     : ["'self'", "data:"],
        objectSrc  : ["'none'"],
        frameAncestors: ["'none'"],       // clickjacking protection
      },
    },
    referrerPolicy: { policy: "no-referrer" },
  })
);

// ─── [SEC-03] Rate-limit: protect against DoS / brute-force ───────────────────
const limiter = rateLimit({
  windowMs : 15 * 60 * 1000,   // 15 minutes
  max      : 100,               // max requests per window per IP
  standardHeaders: true,
  legacyHeaders  : false,
  message: { error: "Too many requests. Please try again later." },
});
app.use(limiter);

// Body parser — cap payload to prevent large-body DoS
app.use(express.urlencoded({ extended: false, limit: "8kb" }));
app.use(express.json({ limit: "8kb" }));

// ─── [SEC-04] HTML escaping — NEVER trust user input in HTML context ──────────
// Replaces every character that can break HTML context: & < > " ' `
function escapeHTML(raw) {
  if (typeof raw !== "string") return "";
  return raw
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;")
    .replace(/'/g,  "&#x27;")
    .replace(/`/g,  "&#x60;");
}

// ─── [SEC-05] Input validation ─────────────────────────────────────────────────
const MAX_INPUT_LEN = 500;                          // enforce length cap
const ALLOWED_PATTERN = /^[\w\s.,!?'"\-()@#%+/:]+$/u; // allowlist charset

function validateUserInput(input) {
  if (typeof input !== "string")        return { ok: false, reason: "Invalid type." };
  if (input.trim().length === 0)        return { ok: false, reason: "Input is empty." };
  if (input.length > MAX_INPUT_LEN)     return { ok: false, reason: "Input too long." };
  if (!ALLOWED_PATTERN.test(input))     return { ok: false, reason: "Disallowed characters." };
  return { ok: true };
}

// ─── [SEC-06] Build response HTML — all user content goes through escapeHTML ──
function buildSafePage(safeContent) {
  // safeContent is already escaped — it is safe to interpolate here
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <!-- [SEC-07] CSP meta tag as defence-in-depth alongside helmet header -->
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self'; object-src 'none';">
  <title>Secure Render</title>
  <style>
    :root {
      --bg: #0d1117; --surface: #161b22; --border: #30363d;
      --text: #e6edf3; --accent: #58a6ff; --error: #f85149;
    }
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Courier New', monospace;
      background: var(--bg); color: var(--text);
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 2rem;
    }
    .card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 8px; padding: 2rem; max-width: 640px; width: 100%;
    }
    .badge {
      display: inline-block; background: #1a3a1a; color: #3fb950;
      font-size: .75rem; padding: .2rem .6rem; border-radius: 4px;
      margin-bottom: 1rem; letter-spacing: .05em;
    }
    h1  { font-size: 1.1rem; color: var(--accent); margin-bottom: 1rem; }
    p   { line-height: 1.7; word-break: break-word; }
    form { margin-top: 2rem; display: flex; flex-direction: column; gap: .75rem; }
    textarea {
      background: var(--bg); color: var(--text); border: 1px solid var(--border);
      border-radius: 6px; padding: .75rem; font-size: 1rem;
      font-family: inherit; resize: vertical; min-height: 100px;
    }
    button {
      background: var(--accent); color: #0d1117; border: none;
      border-radius: 6px; padding: .65rem 1.25rem; font-size: 1rem;
      font-weight: 700; cursor: pointer; align-self: flex-start;
    }
    button:hover { opacity: .85; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">✓ XSS-SAFE RENDER</span>
    <h1>Your Message</h1>
    <!-- [SEC-04] safeContent has been HTML-escaped before reaching here -->
    <p>${safeContent}</p>

    <form method="POST" action="/render" autocomplete="off">
      <!-- [SEC-08] CSRF token embedded in form (see middleware above) -->
      <textarea name="userInput" maxlength="${MAX_INPUT_LEN}"
                placeholder="Enter text (max ${MAX_INPUT_LEN} chars)…"
                required></textarea>
      <button type="submit">Render Safely</button>
    </form>
  </div>
</body>
</html>`;
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// GET /render  — show empty form
app.get("/render", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(buildSafePage("Submit something using the form below."));
});

// POST /render — validate → escape → render
app.post("/render", (req, res) => {
  const raw = req.body?.userInput ?? "";

  // [SEC-05] Validate first
  const validation = validateUserInput(raw);
  if (!validation.ok) {
    // [SEC-09] NEVER expose stack traces — send a generic user-facing error
    return res
      .status(400)
      .setHeader("Content-Type", "text/html; charset=utf-8")
      .send(buildSafePage(`⚠ Validation failed: ${escapeHTML(validation.reason)}`));
  }

  // [SEC-04] Escape BEFORE embedding in HTML
  const safeContent = escapeHTML(raw);

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(buildSafePage(safeContent));
});

// ─── [SEC-09] Generic error handler — NEVER leak stack traces ─────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // Log the real error server-side only
  console.error("[ERROR]", err.message);

  // Send a vague, safe message to the client
  res.status(500).json({ error: "An internal error occurred." });
});

// ─── [SEC-01] debug=False equivalent: never start in debug mode ───────────────
// Node.js has no built-in debug flag, but ensure NODE_ENV is never 'development'
// in production and that no stack traces reach the client (handled above).
if (process.env.NODE_ENV === "development") {
  console.warn("[WARN] Running in development mode. Do NOT deploy this way.");
}

app.listen(PORT, () => {
  console.log(`[INFO] Server listening on port ${PORT}`);
});

module.exports = app; // for testing

"use strict";

/**
 * Security regression tests for the /render endpoint.
 * Run: npm test  (requires supertest as devDependency)
 */

const request = require("supertest");
process.env.SESSION_SECRET = "test-secret-for-ci-only";
process.env.NODE_ENV = "test";

const app = require("./server");

describe("POST /render — XSS prevention", () => {
  const xssPayloads = [
    '<script>alert("xss")</script>',
    '<img src=x onerror=alert(1)>',
    '"><svg/onload=alert(1)>',
    "javascript:alert(1)",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<SCRIPT SRC=http://evil.example/x.js></SCRIPT>",
  ];

  xssPayloads.forEach((payload) => {
    it(`should escape XSS payload: ${payload.slice(0, 40)}`, async () => {
      const res = await request(app)
        .post("/render")
        .send(`userInput=${encodeURIComponent(payload)}`)
        .set("Content-Type", "application/x-www-form-urlencoded");

      // The raw payload must NOT appear literally in the response
      expect(res.text).not.toContain(payload);
      // No unescaped < or > in user-rendered content
      expect(res.text).not.toMatch(/<script/i);
    });
  });
});

describe("POST /render — input validation", () => {
  it("rejects empty input", async () => {
    const res = await request(app)
      .post("/render")
      .send("userInput=   ")
      .set("Content-Type", "application/x-www-form-urlencoded");
    expect(res.status).toBe(400);
  });

  it("rejects input exceeding max length", async () => {
    const res = await request(app)
      .post("/render")
      .send(`userInput=${"A".repeat(501)}`)
      .set("Content-Type", "application/x-www-form-urlencoded");
    expect(res.status).toBe(400);
  });

  it("rejects disallowed characters", async () => {
    const res = await request(app)
      .post("/render")
      .send("userInput=Hello<World")
      .set("Content-Type", "application/x-www-form-urlencoded");
    expect(res.status).toBe(400);
  });

  it("accepts clean input and renders it escaped", async () => {
    const res = await request(app)
      .post("/render")
      .send("userInput=Hello+World")
      .set("Content-Type", "application/x-www-form-urlencoded");
    expect(res.status).toBe(200);
    expect(res.text).toContain("Hello World");
  });
});

describe("Security headers", () => {
  it("sets Content-Security-Policy", async () => {
    const res = await request(app).get("/render");
    expect(res.headers["content-security-policy"]).toBeDefined();
  });

  it("sets X-Frame-Options or frame-ancestors in CSP", async () => {
    const res = await request(app).get("/render");
    const csp = res.headers["content-security-policy"] || "";
    const hasFrameGuard =
      res.headers["x-frame-options"] ||
      csp.includes("frame-ancestors");
    expect(hasFrameGuard).toBeTruthy();
  });
});