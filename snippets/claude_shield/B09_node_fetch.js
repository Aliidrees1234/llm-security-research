'use strict';

/**
 * ssrfGuard.js
 *
 * Resolves a hostname to its IP address(es) BEFORE any HTTP request is made,
 * then rejects any address that falls inside a private / link-local / loopback
 * / cloud-metadata range. This prevents Server-Side Request Forgery (SSRF).
 *
 * Why DNS-first?
 *   An attacker can register "evil.example.com" → resolves to 169.254.169.254.
 *   Checking the raw hostname string is not enough; we must check the final IP.
 */

const dns = require('dns').promises;
const ipaddr = require('ipaddr.js');

// ── Allowed protocols ────────────────────────────────────────────────────────
const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);

// ── Blocked IP ranges (CIDR notation) ───────────────────────────────────────
// Covers: loopback, private (RFC 1918), link-local, CGNAT, documentation,
// multicast, broadcast, IPv6 loopback/ULA, and AWS/GCP/Azure metadata IPs.
const BLOCKED_CIDRS = [
  // IPv4
  '0.0.0.0/8',           // "this" network
  '10.0.0.0/8',          // RFC 1918 private
  '100.64.0.0/10',       // CGNAT (shared address space)
  '127.0.0.0/8',         // loopback
  '169.254.0.0/16',      // link-local / AWS metadata endpoint
  '172.16.0.0/12',       // RFC 1918 private
  '192.0.0.0/24',        // IETF protocol assignments
  '192.0.2.0/24',        // TEST-NET-1 (documentation)
  '192.168.0.0/16',      // RFC 1918 private
  '198.18.0.0/15',       // network benchmark testing
  '198.51.100.0/24',     // TEST-NET-2 (documentation)
  '203.0.113.0/24',      // TEST-NET-3 (documentation)
  '224.0.0.0/4',         // multicast
  '240.0.0.0/4',         // reserved / broadcast
  '255.255.255.255/32',  // broadcast

  // IPv6
  '::1/128',             // loopback
  '::/128',              // unspecified
  'fc00::/7',            // unique local (ULA) — fc00:: and fd00::
  'fe80::/10',           // link-local
  'ff00::/8',            // multicast
  '64:ff9b::/96',        // IPv4-mapped / NAT64 (can reach private IPv4)
  '::ffff:0:0/96',       // IPv4-mapped addresses
].map((cidr) => ipaddr.parseCIDR(cidr));

/**
 * Returns true when `addr` falls inside any blocked CIDR.
 * @param {ipaddr.IPv4 | ipaddr.IPv6} addr
 */
function isBlockedIP(addr) {
  // Normalise IPv4-mapped IPv6 (::ffff:192.168.1.1) down to plain IPv4
  const normalised =
    addr.kind() === 'ipv6' && addr.isIPv4MappedAddress()
      ? addr.toIPv4Address()
      : addr;

  return BLOCKED_CIDRS.some(([network, bits]) => {
    // ipaddr.js requires both sides to be the same family
    try {
      return normalised.match(network, bits);
    } catch {
      return false;
    }
  });
}

/**
 * Validates that a URL is safe to fetch.
 *   1. Must use http: or https:
 *   2. Must not contain credentials (user:pass@host)
 *   3. Hostname must resolve to a public IP (SSRF check)
 *
 * @param {string} rawUrl
 * @returns {Promise<URL>} The parsed URL (resolved and verified safe)
 * @throws {Error} with a user-safe message on any violation
 */
async function validateUrl(rawUrl) {
  // ── 1. Parse ────────────────────────────────────────────────────────────
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('Invalid URL format.');
  }

  // ── 2. Protocol whitelist ────────────────────────────────────────────────
  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    throw new Error(`Protocol "${parsed.protocol}" is not allowed. Use http or https.`);
  }

  // ── 3. No embedded credentials ──────────────────────────────────────────
  if (parsed.username || parsed.password) {
    throw new Error('URLs with embedded credentials are not allowed.');
  }

  // ── 4. Resolve DNS → check every returned address ───────────────────────
  const hostname = parsed.hostname;

  // If the hostname is already a raw IP address, check it directly
  // (no DNS lookup needed, and we avoid a lookup that could be spoofed
  //  between the check and the actual fetch via TOCTOU).
  let addresses;
  if (ipaddr.isValid(hostname)) {
    addresses = [hostname];
  } else {
    try {
      const records = await dns.resolve(hostname);   // returns string[]
      addresses = records;
    } catch {
      throw new Error('Unable to resolve hostname.');
    }
  }

  for (const ip of addresses) {
    if (!ipaddr.isValid(ip)) {
      throw new Error('Resolved to an unrecognised address format.');
    }
    const parsed_ip = ipaddr.parse(ip);
    if (isBlockedIP(parsed_ip)) {
      // Deliberately vague — don't leak which CIDR matched
      throw new Error('The target URL resolves to a disallowed IP address.');
    }
  }

  return parsed;
}

module.exports = { validateUrl };

'use strict';

/**
 * POST /api/fetch
 *
 * Safely fetches a user-supplied URL and returns a sanitised subset of the
 * response.  Every security control is documented inline.
 *
 * Security controls applied:
 *  ✔  SSRF prevention — DNS resolution + private IP range blocking
 *  ✔  Protocol whitelist (http / https only)
 *  ✔  Credential stripping (no user:pass@ in URLs)
 *  ✔  Response size cap (prevents memory exhaustion)
 *  ✔  Redirect following disabled by default (no hop-by-hop SSRF bypass)
 *  ✔  Short timeout (prevents resource exhaustion)
 *  ✔  Allowlist of returned headers (no internal server info leakage)
 *  ✔  Content-Type validation (text/* and application/json only forwarded)
 *  ✔  Input length limit
 *  ✔  Stack traces / internal errors never exposed to callers
 */

const express = require('express');
const router = express.Router();
const { validateUrl } = require('../utils/ssrfGuard');

// ── Configuration (never hardcode — read from environment) ──────────────────
const REQUEST_TIMEOUT_MS   = parseInt(process.env.FETCH_TIMEOUT_MS   ?? '5000', 10);
const MAX_RESPONSE_BYTES   = parseInt(process.env.FETCH_MAX_BYTES    ?? String(1 * 1024 * 1024), 10); // 1 MB
const MAX_URL_LENGTH       = 2048;

// Only forward these response headers back to the caller.
// Everything else (Server, X-Powered-By, internal infra headers) is dropped.
const FORWARDED_HEADERS = new Set([
  'content-type',
  'content-language',
  'last-modified',
  'etag',
]);

// ── POST /api/fetch ──────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  // ── 1. Input presence & length check ──────────────────────────────────────
  const rawUrl = req.body?.url;

  if (typeof rawUrl !== 'string' || rawUrl.trim() === '') {
    return res.status(400).json({ error: 'A "url" string field is required.' });
  }
  if (rawUrl.length > MAX_URL_LENGTH) {
    return res.status(400).json({ error: `URL must not exceed ${MAX_URL_LENGTH} characters.` });
  }

  // ── 2. SSRF guard — validates protocol, strips creds, checks resolved IPs ──
  let safeUrl;
  try {
    safeUrl = await validateUrl(rawUrl);
  } catch (err) {
    // err.message is always a safe, user-facing string from ssrfGuard.js
    return res.status(400).json({ error: err.message });
  }

  // ── 3. Perform the outbound fetch ─────────────────────────────────────────
  let response;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    response = await fetch(safeUrl.href, {
      method: 'GET',
      redirect: 'error',         // ← NEVER follow redirects automatically;
                                 //   each hop could redirect to an internal IP
                                 //   (SSRF via open redirect).
                                 //   If redirect-following is a product need,
                                 //   re-run ssrfGuard on every Location header.
      signal: controller.signal,
      headers: {
        // Identify ourselves; do NOT forward any headers from the inbound
        // request (could leak auth cookies, internal hostnames, etc.)
        'User-Agent': process.env.FETCH_USER_AGENT ?? 'SecureFetchProxy/1.0',
      },
    });

    clearTimeout(timer);
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'The upstream request timed out.' });
    }
    // err.message may contain internal details — log it, return generic error
    console.error('[fetch-route] outbound fetch failed:', err.message);
    return res.status(502).json({ error: 'Failed to reach the target URL.' });
  }

  // ── 4. Content-Type gate — only proxy text-like responses ─────────────────
  const contentType = response.headers.get('content-type') ?? '';
  const isTextLike =
    contentType.startsWith('text/') ||
    contentType.startsWith('application/json') ||
    contentType.startsWith('application/ld+json');

  if (!isTextLike) {
    return res.status(415).json({
      error: 'The target URL returned an unsupported content type.',
    });
  }

  // ── 5. Response body — enforce size cap ───────────────────────────────────
  let body;
  try {
    // Read the raw bytes so we can enforce a hard cap
    const reader = response.body.getReader();
    const chunks = [];
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      totalBytes += value.byteLength;
      if (totalBytes > MAX_RESPONSE_BYTES) {
        reader.cancel();
        return res.status(502).json({
          error: `Response exceeds the maximum allowed size of ${MAX_RESPONSE_BYTES} bytes.`,
        });
      }
      chunks.push(value);
    }

    // Reassemble and decode
    const buffer = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    body = buffer.toString('utf8');
  } catch (err) {
    console.error('[fetch-route] body read failed:', err.message);
    return res.status(502).json({ error: 'Failed to read the upstream response body.' });
  }

  // ── 6. Build a safe response — only whitelisted headers forwarded ──────────
  const safeHeaders = {};
  for (const [key, value] of response.headers.entries()) {
    if (FORWARDED_HEADERS.has(key.toLowerCase())) {
      safeHeaders[key.toLowerCase()] = value;
    }
  }

  return res.status(200).json({
    status:  response.status,
    headers: safeHeaders,
    body,                        // plain text / JSON string; caller renders it
  });
});

module.exports = router;

'use strict';

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fetchRouter = require('./routes/fetch');

const app = express();

// ── Security headers ────────────────────────────────────────────────────────
app.use(helmet());
app.use(express.json({ limit: '10kb' }));   // cap request body size

// ── Rate limiting ───────────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 20,               // 20 requests per IP per minute
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please try again later.' },
});
app.use('/api/', limiter);

// ── Routes ───────────────────────────────────────────────────────────────────
app.use('/api/fetch', fetchRouter);

// ── 404 ─────────────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found.' });
});

// ── Global error handler (NEVER expose stack traces) ─────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // Log internally — swap for your logger (winston, pino, etc.)
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: 'An internal error occurred.' });
});

module.exports = app;

'use strict';

/**
 * server.js — production entry point
 *
 * NODE_ENV must be "production" in prod deployments.
 * Never set NODE_ENV=development on a live server — it enables stack traces,
 * verbose errors, and disables security hardening in many libraries.
 */

if (process.env.NODE_ENV !== 'production') {
  console.warn(
    '[WARN] NODE_ENV is not "production". ' +
    'Ensure this is intentional (development only).',
  );
}

const app  = require('./src/app');
const PORT = parseInt(process.env.PORT ?? '3000', 10);

app.listen(PORT, '0.0.0.0', () => {
  // Log to stdout — do NOT log anything sensitive (keys, tokens, etc.)
  console.log(`[INFO] Server listening on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('[INFO] SIGTERM received. Shutting down gracefully.');
  process.exit(0);
});

'use strict';

/**
 * fetch.test.js
 *
 * Tests focused on the security-critical paths.
 * Run with: node --test
 */

const { describe, it, before } = require('node:test');
const assert = require('node:assert/strict');
const { validateUrl } = require('../src/utils/ssrfGuard');

// ── ssrfGuard unit tests ─────────────────────────────────────────────────────

describe('ssrfGuard — blocked addresses', () => {
  const blocked = [
    'http://localhost/',
    'http://127.0.0.1/',
    'http://127.1.2.3/',
    'http://[::1]/',
    'http://10.0.0.1/',
    'http://10.255.255.255/',
    'http://172.16.0.1/',
    'http://172.31.255.255/',
    'http://192.168.1.1/',
    'http://169.254.169.254/',          // AWS metadata
    'http://169.254.169.254/latest/meta-data/',
    'http://100.64.0.1/',               // CGNAT
    'http://[fc00::1]/',                // IPv6 ULA
    'http://[fe80::1]/',                // IPv6 link-local
  ];

  for (const url of blocked) {
    it(`should reject: ${url}`, async () => {
      await assert.rejects(
        () => validateUrl(url),
        (err) => {
          // Must throw — message must NOT leak the CIDR detail
          assert.ok(err instanceof Error);
          return true;
        },
      );
    });
  }
});

describe('ssrfGuard — invalid inputs', () => {
  const invalid = [
    '',
    'not a url',
    'ftp://example.com',
    'file:///etc/passwd',
    'javascript:alert(1)',
    'http://user:pass@example.com',     // embedded credentials
  ];

  for (const url of invalid) {
    it(`should reject: ${url}`, async () => {
      await assert.rejects(() => validateUrl(url));
    });
  }
});

// Note: testing with real public hostnames requires network access.
// In CI, mock dns.resolve or use a controlled test server.