'use strict';

// ── Blink server ─────────────────────────────────────────────────────────────
// Express app for the whole backend: creating/revealing view-once encrypted
// secrets, the optional passphrase/email-OTP gates on a reveal, Pro
// licensing (Paddle subscriptions) behind Google/GitHub sign-in, rate
// limiting, and the in-memory store with graceful-restart snapshotting. See
// the README's "Key architecture" section for the K1-K4 model this file
// implements; this is the only place K3/K4 and the license store live.
// AES-GCM decryption itself never happens here, on purpose - this server
// only ever sees ciphertext and key *halves*, never the complete key or any
// plaintext; see unmaskK2() below and clientDecrypt() in public/view.js.

const express      = require('express');
const crypto       = require('node:crypto');
const fs           = require('node:fs');
const path         = require('node:path');
const { Resend }   = require('resend');
const { Paddle, Environment } = require('@paddle/paddle-node-sdk');
const pinoHttp     = require('pino-http');

const { RateLimiter }  = require('./lib/ratelimiter');
const { logger, LOGS_DIR, flushLogs } = require('./lib/logger');

const { version: APP_VERSION } = require('./package.json');

const app = express();

// Every persisted file under the data directory (licenses, secrets/rate-limit
// snapshots, stats) holds either real credentials or encrypted secret state,
// so both the directory and the files themselves are created non-world/group
// readable rather than left to the process umask. Each save goes through a
// temp-file-then-rename (see saveLicenses() etc. below), so a file that
// predates this restriction gets corrected to 0600 the next time it's saved,
// not just on first creation.
const SENSITIVE_DIR_MODE  = 0o700;
const SENSITIVE_FILE_MODE = 0o600;

// Every call out to Google/GitHub below went through plain fetch() with no
// timeout - if any of those ever hung (not even down, just slow), the
// request handling it would hang right along with it, for as long as the
// client stayed connected. AbortSignal.timeout() turns that into a bounded,
// catchable error instead.
const EXTERNAL_API_TIMEOUT_MS = 8_000;
function fetchWithTimeout(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(EXTERNAL_API_TIMEOUT_MS) });
}

// ── Trust reverse proxy (Docker bridge, plus whatever each deployment adds) ─
// Used to be a bare hop count (`trust proxy, 2`): trusts the 2 rightmost
// X-Forwarded-For entries unconditionally, no matter whose IP they actually
// are. That only stays correct as long as the request path never changes -
// if the origin ever became directly reachable, anyone could hand-craft a
// 2-entry X-Forwarded-For and have Express believe whatever client IP they
// put first.
//
// 'uniquelocal' is the one hop this project can assume for everyone: the
// included docker-compose.yml always puts this behind a reverse proxy on
// the same host, reached through Docker's own bridge network - Docker's
// userland proxy (the host's published-port listener) connects in from the
// bridge gateway (a private RFC1918 address), not literally 127.0.0.1, so
// that hop needs trusting unconditionally for req.ip to resolve past
// Docker's own NAT at all.
//
// Anything in front of that reverse proxy - a CDN, a tunnel, nothing - is a
// per-deployment choice this project can't assume (Blink is self-hosted;
// hard-coding one provider's IP ranges here would be wrong for anyone not
// using it). TRUSTED_PROXIES lets each operator say what else to trust: a
// comma-separated list of IPs/CIDRs, or the special values 'loopback' /
// 'linklocal' / 'uniquelocal' that `proxy-addr` (Express's own trust-proxy
// implementation) understands. For a deployment behind Cloudflare, for
// example, that means Cloudflare's current published ranges - copy them
// from https://www.cloudflare.com/ips/ when setting this up, not from
// memory or an old copy, since they do change over time.
//
// Leaving TRUSTED_PROXIES unset trusts only the Docker-bridge hop, correct
// for a deployment with nothing but the bundled reverse proxy in front -
// but wrong (silently misattributing every visitor to one rotating edge IP,
// breaking every IP-keyed rate limiter and the `ip` field on every log
// line) for a deployment that adds a CDN/proxy in front of that without
// also setting this.
const TRUSTED_PROXIES = (process.env.TRUSTED_PROXIES || '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
app.set('trust proxy', ['uniquelocal', ...TRUSTED_PROXIES]);

// ── Request logging ──────────────────────────────────────────────────────────
// Every request still gets req.log attached (route handlers log their own
// business events through it, carrying the same request id, so a single
// request's whole story can be traced by id) — but the automatic "request
// completed" line is only emitted for /api/* traffic, where the actions
// actually are. Static assets and plain page loads (CSS, JS, images, /,
// /about, /view/:id, ...) would otherwise produce one log line per file on
// every page load, which is pure noise next to the business-event logs
// already scattered through the API routes. Errors are never silenced by
// this: the global error handler and the 404 handler below log explicitly,
// regardless of path, independent of this ignore rule.
app.use(pinoHttp({
  logger,
  autoLogging: {
    ignore(req) { return !req.url.startsWith('/api/'); },
  },
  customLogLevel(_req, res, err) {
    if (err || res.statusCode >= 500) return 'error';
    if (res.statusCode >= 400) return 'warn';
    return 'info';
  },
  customSuccessMessage(req, res) {
    return `${req.method} ${req.url} ${res.statusCode}`;
  },
  customErrorMessage(req, res, err) {
    return `${req.method} ${req.url} ${res.statusCode} - ${err.message}`;
  },
  // pino-http's own req.remoteAddress reads the raw TCP socket, which behind
  // nginx/Cloudflare is always the reverse proxy's address, not the visitor's
  // - useless for "who actually did this." req.ip is Express's own address,
  // already trust-proxy-aware (see the app.set('trust proxy', ...) call
  // above, which the rate limiters already rely on for the same reason) and
  // resolves to the real client IP. customProps runs per-request, so it sees the same
  // req.ip every route handler does. Added here, not as a replacement for
  // remoteAddress, so both are visible: `ip` for attribution, remoteAddress
  // for proxy-layer debugging if that's ever actually what's being debugged.
  customProps(req) {
    return { ip: req.ip };
  },
}));

// ── Branding (optional) ──────────────────────────────────────────────────────
// Nothing here has a hardcoded default pointing at this deployment's own
// domain/CDN - a self-hoster who doesn't set LOGO_URL just gets emails with
// no logo image (still shows the "Blink" wordmark text) instead of someone
// else's branding; the CSP's img-src only widens to LOGO_URL's own origin
// when it's actually set.
const LOGO_URL = process.env.LOGO_URL || null;
let LOGO_ORIGIN = null;
if (LOGO_URL) {
  try { LOGO_ORIGIN = new URL(LOGO_URL).origin; }
  catch { logger.warn('LOGO_URL is not a valid URL, ignoring it'); }
}

// ── Security headers ────────────────────────────────────────────────────────
// CSP default-src 'none' plus narrow allowlists per directive: every
// resource type must be explicitly opted in, so a new script/style/image
// source added anywhere in the frontend fails closed until it's added here
// too. LOGO_ORIGIN (above) is the only external image origin, added only
// when LOGO_URL is configured.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options',     'nosniff');
  res.setHeader('X-Frame-Options',            'DENY');
  res.setHeader('X-XSS-Protection',           '0');
  res.setHeader('Referrer-Policy',            'no-referrer');
  // The homepage alone needs the Payment Request API available to delegate
  // into Paddle's checkout iframe (Apple Pay/Google Pay buttons) - every
  // other page keeps payment fully disabled.
  res.setHeader('Permissions-Policy', req.path === '/'
    ? 'camera=(), microphone=(), geolocation=(), payment=(self)'
    : 'camera=(), microphone=(), geolocation=(), payment=()');
  res.setHeader('Cross-Origin-Opener-Policy',   'same-origin');
  // COEP requires every cross-origin resource (including an <iframe>) to
  // send a matching header back, which youtube-nocookie.com's embed does
  // not - both /about's demo video and /'s first-visit intro video popup
  // would otherwise fail to load with ERR_BLOCKED_BY_RESPONSE. Nothing on
  // this site needs cross-origin isolation (no SharedArrayBuffer/WASM
  // threads), so this is safe to skip on the pages that embed something.
  if (req.path !== '/about' && req.path !== '/') {
    res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
  }
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // Paddle Checkout (the "Get Pro" button) is the one script/frame this site
  // ever loads from a third party, and it only lives on the homepage - every
  // other page keeps the fully self-hosted script-src/frame-src. cdn.paddle.com
  // serves Paddle.js itself; the checkout iframe it opens is served from
  // Paddle's own domain, which Paddle does not publish a single fixed
  // hostname for, so this allows the whole *.paddle.com family rather than
  // guessing one subdomain that could change without notice. Paddle.js also
  // positions/styles that overlay iframe via inline style="" attributes and
  // an injected <style> tag (confirmed via securitypolicyviolation events,
  // not guessed) - without 'unsafe-inline' here the checkout silently
  // renders unstyled at the bottom of the page instead of as an overlay.
  const isHomepage = req.path === '/';
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'none'",
      `script-src 'self'${isHomepage ? ' https://cdn.paddle.com' : ''}`,
      `style-src 'self'${isHomepage ? " 'unsafe-inline'" : ''}`,
      "font-src 'self'",
      `img-src 'self' data:${LOGO_ORIGIN ? ` ${LOGO_ORIGIN}` : ''}`,
      // api.github.com is called client-side by github-stars.js, straight
      // from each visitor's own browser - never through this server.
      `connect-src 'self' https://api.github.com${isHomepage ? ' https://*.paddle.com' : ''}`,
      "manifest-src 'self'",
      "worker-src 'self'",
      // The about page's demo video is the one embedded frame on the site -
      // youtube-nocookie.com is YouTube's privacy-enhanced embed domain
      // (no tracking cookies until playback actually starts).
      `frame-src https://www.youtube-nocookie.com${isHomepage ? ' https://*.paddle.com' : ''}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
    ].join('; ')
  );
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  }
  next();
});

// ── HTTPS redirect (production only) ───────────────────────────────────────
// Uses a configured HOST env var to avoid open-redirect via attacker-controlled Host header.
if (process.env.NODE_ENV === 'production' && process.env.HOST) {
  const CANONICAL_HOST = process.env.HOST; // e.g. "yourdomain.com"
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(301, `https://${CANONICAL_HOST}${req.url}`);
    }
    next();
  });
}

// ── Rate limiters (configurable via env for testing) ───────────────────────
const createLimiter = new RateLimiter(60_000,    parseInt(process.env.CREATE_RATE_LIMIT || '10',  10), 'create');
const readLimiter   = new RateLimiter(60_000,    parseInt(process.env.READ_RATE_LIMIT   || '30',  10), 'read');
const emailLimiter  = new RateLimiter(3_600_000, parseInt(process.env.EMAIL_RATE_LIMIT  || '3',   10), 'email');
// Bucketed by the signed-in account, so every session using the same
// license — however it ended up authenticated — shares one daily quota. This
// is now a secondary safety net: the real protection is that Pro requires a
// live session per account (Activation Limit = 1), not a copy-pasteable
// key. This limiter just guards against runaway/automated abuse of one account.
const licenseUsageLimiter = new RateLimiter(86_400_000, parseInt(process.env.PRO_USAGE_RATE_LIMIT || '50', 10), 'pro-usage');
// Free tier has no account concept, so this is bucketed by IP — the only
// signal available for an anonymous creator.
const freeUsageLimiter = new RateLimiter(86_400_000, parseInt(process.env.FREE_USAGE_RATE_LIMIT || '5', 10), 'free-usage');

// All five share one list purely so the snapshot below can loop over them —
// the limiters themselves are otherwise unrelated and bucket independently.
const allRateLimiters = [createLimiter, readLimiter, emailLimiter, licenseUsageLimiter, freeUsageLimiter];

// ── Blink Pro licensing (Paddle subscriptions + Google/GitHub Sign-In) ──────
// Unlike Lemon Squeezy, Paddle has no hosted "license key" API - no
// activate/deactivate/validate endpoints to call. Blink mints and checks its
// own keys instead; a Paddle webhook (POST /api/webhooks/paddle, below) is
// the ONLY thing that ever creates one or flips its status, driven by real
// subscription events, never by this server polling Paddle.
//
// The key itself lives ONLY on the server, keyed by a hash of the signed-in
// account's verified email — never in the browser. The browser only ever
// holds a signed session cookie proving "this email is logged in right
// now." Keying by email (rather than a provider-specific account ID) is
// deliberate: it's what makes Google and GitHub sign-in resolve to the SAME
// Pro account whenever both are verified for the same address. Two
// different emails are, correctly, two different accounts — no linking
// happens unless the email itself matches.
// A raw license key pasted into a chat is just a copy-pasteable string; a
// live OAuth login is not something people hand out the same way, which is
// what actually stops casual key sharing - enforced below by rejecting
// activation onto a second account (paddleLicenses[key].boundAccountHash),
// the local equivalent of Lemon Squeezy's "Activation Limit = 1".
const PADDLE_API_KEY        = process.env.PADDLE_API_KEY        || null;
const PADDLE_WEBHOOK_SECRET = process.env.PADDLE_WEBHOOK_SECRET || null;
// Only used by the webhook handler below to verify signatures and (for
// subscription events) look up the paying customer's email - never to
// create a checkout; the browser opens checkout itself via Paddle.js and
// the public PADDLE_CLIENT_TOKEN (see GET /api/config), so this key never
// needs to reach the frontend.
const paddleClient = PADDLE_API_KEY
  ? new Paddle(PADDLE_API_KEY, { environment: process.env.PADDLE_ENV === 'sandbox' ? Environment.sandbox : Environment.production })
  : null;
const PRO_DEV_KEY = process.env.BLINK_PRO_DEV_KEY || null;
// Site owner allowlist — these accounts (by email, either sign-in provider)
// always have Pro, no license or Paddle involved. Safer than a shared
// bearer key for this: even if the env var leaked, it only grants Pro to a
// specific real, provider-verified email, not to anyone who happens to read
// the value. Comma-separated in OWNER_EMAILS.
const OWNER_EMAILS = new Set(
  (process.env.OWNER_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)
);
const LICENSE_KEY_RE = /^[A-Za-z0-9-]{8,64}$/;

// Four groups of 5 base32-ish characters, e.g. "BLINK-7F3KQ-9M2XH-4YTRZ-C8WPL" -
// readable over email, unambiguous enough to type back in by hand, and well
// inside LICENSE_KEY_RE above.
function generateLicenseKey() {
  const raw = crypto.randomBytes(16).toString('base64url').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return `BLINK-${raw.slice(0, 20).match(/.{1,5}/g).join('-')}`;
}

// Mints a fresh key for a newly-activated Paddle subscription. Idempotent by
// subscriptionId: Paddle delivers webhooks at-least-once, so a retried
// subscription.activated must never issue a second key for the same
// subscription - it just returns the one already on file.
function issueLicenseKey(email, subscriptionId) {
  for (const [key, record] of Object.entries(paddleLicenses)) {
    if (record.subscriptionId === subscriptionId) return key;
  }
  let key;
  do { key = generateLicenseKey(); } while (paddleLicenses[key]);
  paddleLicenses[key] = { email, subscriptionId, status: 'active', boundAccountHash: null, issuedAt: Date.now() };
  savePaddleLicenses();
  return key;
}

// Mirrors a subscription's current Paddle status onto every license key
// issued for it - in practice exactly one, but matching on subscriptionId
// rather than assuming that keeps this correct even if that ever changes.
function updateSubscriptionStatus(subscriptionId, status) {
  for (const record of Object.values(paddleLicenses)) {
    if (record.subscriptionId === subscriptionId) record.status = status;
  }
  savePaddleLicenses();
}

// Binds `key` to `accountHash`, enforcing a one-account-per-key limit purely
// from local state - no network call, so nothing here can be "unavailable".
function activateLicense(key, accountHash) {
  const record = paddleLicenses[key];
  if (record?.status !== 'active') return { ok: false, error: 'invalid' };
  if (record.boundAccountHash && record.boundAccountHash !== accountHash) {
    return { ok: false, error: 'activation_limit' };
  }
  record.boundAccountHash = accountHash;
  savePaddleLicenses();
  return { ok: true };
}

function deactivateLicense(key, accountHash) {
  const record = paddleLicenses[key];
  if (record && record.boundAccountHash === accountHash) {
    record.boundAccountHash = null;
    savePaddleLicenses();
  }
}

function isLicenseValid(key) {
  return paddleLicenses[key]?.status === 'active';
}

// ── Persistent license store, keyed by a hash of the account's verified email ──
// { [sha256(email.toLowerCase())]: { licenseKey, instanceId, email, activatedAt } }
// Never sent to the browser — only the session cookie is. Mirrors the
// STATS_FILE persistence pattern already used elsewhere in this file.
const LICENSES_FILE = process.env.LICENSES_FILE || path.join(__dirname, 'data', 'licenses.json');
let licenses = {};

try {
  fs.mkdirSync(path.dirname(LICENSES_FILE), { recursive: true, mode: SENSITIVE_DIR_MODE });
  licenses = JSON.parse(fs.readFileSync(LICENSES_FILE, 'utf8'));
} catch {}

// One-time migration: older records were keyed by a hash of the Google
// account's "sub" ID rather than email. Re-key anything we can (every record
// already stores its email) so Google and GitHub sign-in start resolving to
// the same account immediately, instead of only for newly-activated licenses.
{
  let migrated = false;
  for (const [oldKey, record] of Object.entries(licenses)) {
    if (!record?.email) continue;
    const newKey = emailHash(record.email);
    if (newKey === oldKey) continue; // already keyed correctly
    if (licenses[newKey]) {
      logger.warn({ oldKey, newKey }, 'license migration: email already has a record under the new key, leaving old key in place for manual review');
      continue;
    }
    licenses[newKey] = record;
    delete licenses[oldKey];
    migrated = true;
  }
  if (migrated) saveLicenses(); // hoisted function, defined just below
}

function saveLicenses() {
  try {
    const tmp = LICENSES_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(licenses, null, 2), { mode: SENSITIVE_FILE_MODE });
    fs.renameSync(tmp, LICENSES_FILE);
  } catch (err) {
    logger.error({ err }, 'failed to persist licenses file');
  }
}

// ── Persistent Paddle license registry, keyed by the license key itself ────
// { [licenseKey]: { email, subscriptionId, status, boundAccountHash, issuedAt } }
// The global source of truth for "does this key exist and is it currently
// active" - `licenses` above only ever stores which key an ACCOUNT has
// bound, not whether that key is still good, which is why both stores exist
// side by side. Separate file from LICENSES_FILE so upgrading a deployment
// from Lemon Squeezy/Polar never has to migrate or guess at an old record's
// shape - Pro accounts simply re-activate with a freshly-issued Paddle key.
const PADDLE_LICENSES_FILE = process.env.PADDLE_LICENSES_FILE || path.join(__dirname, 'data', 'paddle-licenses.json');
let paddleLicenses = {};

try {
  fs.mkdirSync(path.dirname(PADDLE_LICENSES_FILE), { recursive: true, mode: SENSITIVE_DIR_MODE });
  paddleLicenses = JSON.parse(fs.readFileSync(PADDLE_LICENSES_FILE, 'utf8'));
} catch {}

function savePaddleLicenses() {
  try {
    const tmp = PADDLE_LICENSES_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(paddleLicenses, null, 2), { mode: SENSITIVE_FILE_MODE });
    fs.renameSync(tmp, PADDLE_LICENSES_FILE);
  } catch (err) {
    logger.error({ err }, 'failed to persist paddle-licenses file');
  }
}

// ── Signed session cookies ──────────────────────────────────────────────────
// Hand-rolled (one HMAC-signed cookie) instead of adding a cookie-parser /
// express-session dependency for something this simple.
const SESSION_SECRET     = process.env.SESSION_SECRET || null;
const SESSION_COOKIE     = 'blink_session';
const SESSION_MAX_AGE    = 7 * 24 * 3_600_000; // 7 days

// Per-provider, not a single shared name: with one cookie, starting a Google
// sign-in in one tab and a GitHub sign-in in another (or just retrying)
// overwrites the first flow's state/verifier before its callback runs,
// failing it with a false "mismatched state".
function oauthStateCookieName(provider)    { return `blink_oauth_state_${provider}`; }
function oauthVerifierCookieName(provider) { return `blink_oauth_verifier_${provider}`; }

// PKCE (RFC 7636): binds the authorization code to this specific browser
// round-trip, so a code that leaks somewhere along the redirect chain (a
// referrer header, a proxy log) can't be replayed by someone who doesn't
// also have the verifier. Both Google and GitHub document support for the
// S256 challenge method on their standard OAuth authorization-code flow.
function generatePkcePair() {
  const verifier  = crypto.randomBytes(32).toString('base64url'); // 43 chars - meets RFC 7636's 43-128 range
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function parseCookies(header) {
  // Keys come straight from the raw Cookie header (attacker-controlled).
  // A null-prototype object means a key like "__proto__" or "constructor"
  // just becomes an own property, never a prototype-pollution vector.
  const out = Object.create(null);
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) { try { out[k] = decodeURIComponent(v); } catch { out[k] = v; } }
  }
  return out;
}

function signValue(value, secret) {
  const sig = crypto.createHmac('sha256', secret).update(value).digest('base64url');
  return `${value}.${sig}`;
}

function unsignValue(signed, secret) {
  const idx = signed.lastIndexOf('.');
  if (idx === -1) return null;
  const value = signed.slice(0, idx);
  const sig   = signed.slice(idx + 1);
  const expected = crypto.createHmac('sha256', secret).update(value).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return value;
}

// The one identity key shared across every sign-in provider: whichever
// provider you authenticate with, this is what actually gets looked up in
// `licenses`. Same verified email -> same hash -> same Pro account.
function emailHash(email) {
  return crypto.createHash('sha256').update(String(email).toLowerCase()).digest('hex');
}

function cookieAttrs(maxAgeSeconds) {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return `HttpOnly${secure}; SameSite=Lax; Path=/; Max-Age=${maxAgeSeconds}`;
}

function setSessionCookie(res, subHash, email) {
  const payload = JSON.stringify({ sub: subHash, email: email || null, exp: Date.now() + SESSION_MAX_AGE });
  const value   = signValue(Buffer.from(payload).toString('base64url'), SESSION_SECRET);
  res.append('Set-Cookie', `${SESSION_COOKIE}=${value}; ${cookieAttrs(Math.floor(SESSION_MAX_AGE / 1000))}`);
}

function clearSessionCookie(res) {
  res.append('Set-Cookie', `${SESSION_COOKIE}=; ${cookieAttrs(0)}`);
}

function readSession(req) {
  if (!SESSION_SECRET) return null;
  const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!raw) return null;
  const encoded = unsignValue(raw, SESSION_SECRET);
  if (!encoded) {
    // Signature didn't match — either a forged/tampered cookie, or an old
    // one signed under a SESSION_SECRET that's since been rotated. Worth
    // knowing about either way; this is otherwise indistinguishable from
    // "not logged in" anywhere else in the request's handling.
    req.log?.warn('session cookie present but signature invalid');
    return null;
  }
  try {
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (typeof payload.sub !== 'string' || typeof payload.exp !== 'number') {
      req.log?.warn('session cookie present but malformed payload');
      return null;
    }
    if (Date.now() > payload.exp) {
      req.log?.debug({ account: payload.sub }, 'session cookie expired');
      return null;
    }
    return payload;
  } catch {
    req.log?.warn('session cookie present but not valid JSON');
    return null;
  }
}

async function isProForSession(session) {
  if (!session) return false;
  if (session.email && OWNER_EMAILS.has(session.email.toLowerCase())) return true;
  const record = licenses[session.sub];
  if (!record) return false;
  if (PRO_DEV_KEY && record.licenseKey === PRO_DEV_KEY) return true;
  return isLicenseValid(record.licenseKey);
}

// ── Google OAuth (server-side redirect flow — no client-side Google JS SDK,
// so the strict script-src 'self' CSP never needs loosening) ───────────────
// See the GitHub OAuth block further down for the second sign-in option;
// both resolve to the same account whenever the verified email matches.
const GOOGLE_CLIENT_ID       = process.env.GOOGLE_CLIENT_ID     || null;
const GOOGLE_CLIENT_SECRET   = process.env.GOOGLE_CLIENT_SECRET || null;
const GOOGLE_REDIRECT_URI    = process.env.GOOGLE_REDIRECT_URI  || null;
const GOOGLE_AUTH_CONFIGURED = !!(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET && GOOGLE_REDIRECT_URI && SESSION_SECRET);

app.get('/api/auth/google/start', (req, res) => {
  if (!GOOGLE_AUTH_CONFIGURED) {
    req.log.warn('google sign-in attempted but not configured on this server');
    return res.status(503).send('Google sign-in is not configured on this server.');
  }
  const state = crypto.randomBytes(24).toString('base64url');
  const { verifier, challenge } = generatePkcePair();
  res.append('Set-Cookie', `${oauthStateCookieName('google')}=${state}; ${cookieAttrs(600)}`);
  res.append('Set-Cookie', `${oauthVerifierCookieName('google')}=${verifier}; ${cookieAttrs(600)}`);
  const params = new URLSearchParams({
    client_id:             GOOGLE_CLIENT_ID,
    redirect_uri:          GOOGLE_REDIRECT_URI,
    response_type:         'code',
    scope:                 'openid email',
    state,
    prompt:                'select_account',
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  res.append('Set-Cookie', `${oauthStateCookieName('google')}=; ${cookieAttrs(0)}`);
  res.append('Set-Cookie', `${oauthVerifierCookieName('google')}=; ${cookieAttrs(0)}`);
  if (!GOOGLE_AUTH_CONFIGURED) {
    req.log.warn('google oauth callback hit but not configured on this server');
    return res.status(503).send('Google sign-in is not configured on this server.');
  }
  const { code, state } = req.query;
  const cookies = parseCookies(req.headers.cookie);
  const expectedState = cookies[oauthStateCookieName('google')];
  const verifier       = cookies[oauthVerifierCookieName('google')];
  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    req.log.warn('google oauth callback rejected: missing or mismatched state');
    return res.redirect('/?auth=error');
  }

  try {
    const tokenResp = await fetchWithTimeout('https://oauth2.googleapis.com/token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code:          String(code),
        client_id:     GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri:  GOOGLE_REDIRECT_URI,
        grant_type:    'authorization_code',
        code_verifier: verifier,
      }),
    });
    const tokenData = await tokenResp.json();
    if (!tokenData.id_token) {
      req.log.warn('google oauth callback: token exchange returned no id_token');
      return res.redirect('/?auth=error');
    }

    // Google's own docs call tokeninfo a *debugging* endpoint ("may be
    // throttled or otherwise subject to intermittent errors" in production)
    // and don't document it as enforcing exp itself - both checked here
    // explicitly rather than assumed. The real production-recommended path
    // is local JWKS verification; tokeninfo is kept for now to avoid adding
    // a JWT/JWKS dependency, but see the README/issue tracker for this as a
    // follow-up.
    const infoResp = await fetchWithTimeout(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(tokenData.id_token)}`);
    const info = await infoResp.json();
    const issuerOk = info.iss === 'https://accounts.google.com' || info.iss === 'accounts.google.com';
    const expOk    = Number(info.exp) > Date.now() / 1000;
    if (info.aud !== GOOGLE_CLIENT_ID || info.email_verified !== 'true' || !info.sub || !issuerOk || !expOk) {
      req.log.warn('google oauth callback: tokeninfo failed verification');
      return res.redirect('/?auth=error');
    }

    setSessionCookie(res, emailHash(info.email), info.email);
    req.log.info({ provider: 'google', emailHash: emailHash(info.email) }, 'oauth login succeeded');
    res.redirect('/?auth=success');
  } catch (err) {
    req.log.error({ err, provider: 'google' }, 'oauth callback failed');
    res.redirect('/?auth=error');
  }
});

// ── GitHub OAuth (same server-side redirect flow as Google) ────────────────
// Resolves to the exact same account as Google whenever the verified email
// matches — see emailHash() above and the licenses-store comment. GitHub
// accounts can have a private primary email, so this requires the
// "user:email" scope and reads the dedicated /user/emails endpoint rather
// than the basic /user profile.
const GITHUB_CLIENT_ID       = process.env.GITHUB_CLIENT_ID     || null;
const GITHUB_CLIENT_SECRET   = process.env.GITHUB_CLIENT_SECRET || null;
const GITHUB_REDIRECT_URI    = process.env.GITHUB_REDIRECT_URI  || null;
const GITHUB_AUTH_CONFIGURED = !!(GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET && GITHUB_REDIRECT_URI && SESSION_SECRET);

app.get('/api/auth/github/start', (req, res) => {
  if (!GITHUB_AUTH_CONFIGURED) {
    req.log.warn('github sign-in attempted but not configured on this server');
    return res.status(503).send('GitHub sign-in is not configured on this server.');
  }
  const state = crypto.randomBytes(24).toString('base64url');
  const { verifier, challenge } = generatePkcePair();
  res.append('Set-Cookie', `${oauthStateCookieName('github')}=${state}; ${cookieAttrs(600)}`);
  res.append('Set-Cookie', `${oauthVerifierCookieName('github')}=${verifier}; ${cookieAttrs(600)}`);
  const params = new URLSearchParams({
    client_id:             GITHUB_CLIENT_ID,
    redirect_uri:          GITHUB_REDIRECT_URI,
    scope:                 'read:user user:email',
    state,
    allow_signup:          'true',
    code_challenge:        challenge,
    code_challenge_method: 'S256',
  });
  res.redirect(`https://github.com/login/oauth/authorize?${params.toString()}`);
});

app.get('/api/auth/github/callback', async (req, res) => {
  res.append('Set-Cookie', `${oauthStateCookieName('github')}=; ${cookieAttrs(0)}`);
  res.append('Set-Cookie', `${oauthVerifierCookieName('github')}=; ${cookieAttrs(0)}`);
  if (!GITHUB_AUTH_CONFIGURED) {
    req.log.warn('github oauth callback hit but not configured on this server');
    return res.status(503).send('GitHub sign-in is not configured on this server.');
  }
  const { code, state } = req.query;
  const cookies = parseCookies(req.headers.cookie);
  const expectedState = cookies[oauthStateCookieName('github')];
  const verifier       = cookies[oauthVerifierCookieName('github')];
  if (!code || !state || !expectedState || state !== expectedState || !verifier) {
    req.log.warn('github oauth callback rejected: missing or mismatched state');
    return res.redirect('/?auth=error');
  }

  try {
    const tokenResp = await fetchWithTimeout('https://github.com/login/oauth/access_token', {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: new URLSearchParams({
        code:          String(code),
        client_id:     GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        redirect_uri:  GITHUB_REDIRECT_URI,
        code_verifier: verifier,
      }),
    });
    const tokenData = await tokenResp.json();
    if (!tokenData.access_token) {
      req.log.warn('github oauth callback: token exchange returned no access_token');
      return res.redirect('/?auth=error');
    }

    // GitHub's /user endpoint only returns a public email if the account has
    // one set; the verified primary address lives in /user/emails instead,
    // and requires its own request with the "user:email" scope.
    const emailsResp = await fetchWithTimeout('https://api.github.com/user/emails', {
      headers: {
        'Authorization': `Bearer ${tokenData.access_token}`,
        'Accept':        'application/vnd.github+json',
        'User-Agent':    'blink-app',
      },
    });
    const emails = await emailsResp.json();
    const primary = Array.isArray(emails)
      ? emails.find(e => e.primary && e.verified) || emails.find(e => e.verified)
      : null;
    if (!primary?.email) {
      req.log.warn('github oauth callback: no verified email on account');
      return res.redirect('/?auth=error');
    }

    setSessionCookie(res, emailHash(primary.email), primary.email);
    req.log.info({ provider: 'github', emailHash: emailHash(primary.email) }, 'oauth login succeeded');
    res.redirect('/?auth=success');
  } catch (err) {
    req.log.error({ err, provider: 'github' }, 'oauth callback failed');
    res.redirect('/?auth=error');
  }
});

app.get('/api/auth/me', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) return res.json({ loggedIn: false });
  const isPro   = await isProForSession(session);
  const isOwner = !!(session.email && OWNER_EMAILS.has(session.email.toLowerCase()));
  res.json({ loggedIn: true, email: session.email || null, isPro, isOwner });
});

app.post('/api/auth/logout', (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  clearSessionCookie(res);
  if (session) req.log.info({ account: session.sub }, 'logged out');
  res.json({ ok: true });
});

// Dev-only bypass so the full session -> license flow can be tested locally
// without real Google/GitHub OAuth credentials. Never registered in production.
if (process.env.NODE_ENV !== 'production' && PRO_DEV_KEY) {
  app.get('/api/auth/dev-login', (req, res) => {
    const devEmail = 'dev@example.com';
    setSessionCookie(res, emailHash(devEmail), devEmail);
    req.log.warn('dev-login used: auth bypass session created');
    res.redirect('/?auth=success');
  });
}

// ── Body parsers ─────────────────────────────────────────────────────────────
// Pro uploads (25 MB files) need a larger limit than everything else. Applied
// per-route (not globally) so static assets and other endpoints never pay for
// a session/license lookup on every request.
const jsonSmall = express.json({ limit: '4mb',  strict: true });
const jsonLarge = express.json({ limit: '40mb', strict: true });

// ── Static files (HTML pages served no-store) ──────────────────────────────
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  lastModified: true,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store');
    }
  },
}));

// ── In-memory store ─────────────────────────────────────────────────────────
// Deliberately never touches disk during normal operation - that's what
// makes a VPS compromise or disk forensics unable to recover a pending
// secret. The one exception: a GRACEFUL shutdown (a deploy, `docker compose
// restart`) snapshots this Map to the existing /data volume just before
// exiting, and reloads it on the next startup - see saveSecretsSnapshot()
// and loadSecretsSnapshot() below. This loses nothing extra in security
// terms: every value already stored here is the same encrypted ciphertext
// and K3-masked K2 that would be written to the snapshot, never plaintext,
// never usable without K1 (which never reaches the server). A hard crash,
// SIGKILL, or power loss still loses everything unviewed - there's no
// graceful-shutdown moment to snapshot in that case, same as always.
const secrets     = new Map();
const MAX_SECRETS      = 10_000;
// MAX_SECRETS alone doesn't bound memory: a Pro file secret's ciphertext
// can be ~35MB (base64), so 10,000 of those would be ~350GB, nowhere near
// the container's actual memory limit (512MB by default - see
// docker-compose.yml). This caps the combined ciphertext size actually
// held in memory at once, independent of how many secrets that is.
const MAX_TOTAL_CIPHERTEXT_BYTES = Number(process.env.MAX_SECRETS_BYTES) || 256 * 1024 * 1024;
// ciphertext is always base64 (ASCII-only), so .length (UTF-16 code units)
// and its real byte count are numerically identical - Buffer.byteLength is
// used anyway so this stays correct even if that ever changed, and reads
// honestly as a byte count rather than a string-length stand-in for one.
// It's still only the dominant cost for a *file* secret, though: a text
// secret's own ciphertext is tiny, and this still ignores every other
// stored field (iv, k2, k1Hash, ctIv, otpHash, filename, ...) plus each
// entry's own Map/object overhead in V8 - all real bytes this number would
// otherwise pretend don't exist. PER_SECRET_OVERHEAD_BYTES is a deliberately
// generous fixed estimate covering that, so the total stays a safe upper
// bound even for a store full of many small text secrets, not just a few
// large file ones.
const PER_SECRET_OVERHEAD_BYTES = 512;
function totalStoredCiphertextBytes() {
  let total = 0;
  for (const s of secrets.values()) total += Buffer.byteLength(s.ciphertext, 'utf8') + PER_SECRET_OVERHEAD_BYTES;
  return total;
}
// Checked once up front (cheap fail-fast before any validation/scrypt/email
// work) and again right before secrets.set() in POST /api/secret. Two calls
// because the handler's only await - sending the OTP email, when the request
// asks for one - sits between them: without a check on both sides of it,
// concurrent requests already past the first check could all still be
// in-flight when they each reach secrets.set(), overrunning both caps before
// any of them is reflected in secrets.size/totalStoredCiphertextBytes(). The
// final check has no await after it, so it's effectively atomic per request.
function capacityExceeded(ciphertextLen) {
  return secrets.size >= MAX_SECRETS
    || totalStoredCiphertextBytes() + ciphertextLen + PER_SECRET_OVERHEAD_BYTES > MAX_TOTAL_CIPHERTEXT_BYTES;
}
const ALLOWED_TTL_HOURS     = new Set([1, 6, 24, 48]);
const ALLOWED_TTL_HOURS_PRO = new Set([1, 6, 24, 48, 168]);
const DEFAULT_TTL_HOURS = 48;
const MAX_VIEWS_PRO       = 5;
const PASSPHRASE_MIN_LEN  = 4;
const PASSPHRASE_MAX_LEN  = 128;
const MAX_AUTH_ATTEMPTS   = 5;

const SECRETS_SNAPSHOT_FILE = process.env.SECRETS_SNAPSHOT_FILE || path.join(__dirname, 'data', 'secrets-snapshot.json');

function loadSecretsSnapshot() {
  let raw;
  try {
    raw = fs.readFileSync(SECRETS_SNAPSHOT_FILE, 'utf8');
  } catch {
    return; // normal case: no snapshot exists (last shutdown wasn't graceful, or this is a fresh start)
  }
  // Delete immediately after reading, graceful or not - a snapshot should
  // never linger on disk longer than the one restart it was written for.
  try { fs.unlinkSync(SECRETS_SNAPSHOT_FILE); } catch {}

  let entries;
  try {
    entries = JSON.parse(raw);
  } catch (err) {
    logger.error({ err }, 'secrets snapshot was corrupt, discarding it');
    return;
  }
  if (!Array.isArray(entries)) {
    logger.error({ type: typeof entries }, 'secrets snapshot was not an array, discarding it');
    return;
  }

  const now = Date.now();
  let restored = 0;
  let expired  = 0;
  let rejected = 0;
  let capped   = 0;
  for (const entry of entries) {
    if (!isValidSnapshotEntry(entry)) { rejected++; continue; }
    const [id, secret] = entry;
    if (secret.expiresAt <= now) { expired++; continue; }
    // A corrupted or tampered snapshot could otherwise carry far more
    // entries/bytes than MAX_SECRETS/MAX_TOTAL_CIPHERTEXT_BYTES allow for a
    // live create - those caps exist to keep this server inside its
    // container memory limit, so restoring past them would defeat the point.
    if (capacityExceeded(secret.ciphertext.length)) { capped++; continue; }
    secrets.set(id, secret);
    restored++;
  }
  logger.info({ restored, expired, rejected, capped }, 'secrets restored from graceful-shutdown snapshot');
}

// Structural sanity check on one [id, secret] pair from a restored snapshot,
// not a full semantic re-validation (a K4-wrapped ciphertext's length, for
// example, doesn't follow the same bounds POST /api/secret enforces on a
// fresh submission) - just enough to guarantee every field this file
// actually reads later (ciphertext.length, expiresAt comparisons, etc.)
// is the type it's assumed to be, so a corrupted or hand-edited snapshot
// can't crash the server or silently create an unusable/malformed secret.
// Inlined rather than reusing the shared UUID_RE further down this file:
// that constant isn't defined yet at the point loadSecretsSnapshot() runs
// (module-load time, before the "Validators" section below it), so
// referencing it here would throw on startup.
const SNAPSHOT_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function isNonEmptyString(v) { return typeof v === 'string' && v.length > 0; }
function isNullableString(v) { return v === null || typeof v === 'string'; }
function isNonNegativeInt(v)  { return Number.isInteger(v) && v >= 0; }

function isValidSnapshotEntry(entry) {
  if (!Array.isArray(entry) || entry.length !== 2) return false;
  const [id, secret] = entry;
  if (!SNAPSHOT_UUID_RE.test(id) || !secret || typeof secret !== 'object') return false;
  return isNonEmptyString(secret.ciphertext)
    && isNonEmptyString(secret.iv)
    && isNonEmptyString(secret.k2)
    && isNullableString(secret.k1Hash)
    && isNullableString(secret.ctIv)
    && Number.isFinite(secret.expiresAt)
    && isNonNegativeInt(secret.viewsLeft)
    && isNonNegativeInt(secret.otpAttempts)
    && isNonNegativeInt(secret.passAttempts)
    && typeof secret.isFile === 'boolean';
}

function saveSecretsSnapshot() {
  try {
    const tmp = SECRETS_SNAPSHOT_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify([...secrets.entries()]), { mode: SENSITIVE_FILE_MODE });
    fs.renameSync(tmp, SECRETS_SNAPSHOT_FILE);
    logger.info({ count: secrets.size }, 'secrets snapshotted for graceful restart');
  } catch (err) {
    logger.error({ err }, 'failed to snapshot secrets before shutdown - any unviewed secret will be lost');
  }
}

try { fs.mkdirSync(path.dirname(SECRETS_SNAPSHOT_FILE), { recursive: true, mode: SENSITIVE_DIR_MODE }); } catch {}
loadSecretsSnapshot();

// Same graceful-restart snapshot idea as the secrets Map above, but for
// rate-limiter state: without this, a deploy silently zeroes everyone's
// daily free/pro usage count and resets every in-progress burst window,
// which is a real abuse window (max out the free tier, wait for the next
// deploy, repeat) rather than just a UX surprise.
const RATE_LIMITS_SNAPSHOT_FILE = process.env.RATE_LIMITS_SNAPSHOT_FILE || path.join(__dirname, 'data', 'rate-limits-snapshot.json');

function loadRateLimitsSnapshot() {
  let raw;
  try {
    raw = fs.readFileSync(RATE_LIMITS_SNAPSHOT_FILE, 'utf8');
  } catch {
    return;
  }
  try { fs.unlinkSync(RATE_LIMITS_SNAPSHOT_FILE); } catch {}

  let byName;
  try {
    byName = JSON.parse(raw);
  } catch (err) {
    logger.error({ err }, 'rate limits snapshot was corrupt, discarding it');
    return;
  }

  let restored = 0;
  for (const limiter of allRateLimiters) {
    const entries = byName[limiter.name];
    if (!entries) continue;
    limiter.restore(entries);
    restored++;
  }
  logger.info({ restored }, 'rate limiter state restored from graceful-shutdown snapshot');
}

function saveRateLimitsSnapshot() {
  try {
    const byName = {};
    for (const limiter of allRateLimiters) byName[limiter.name] = limiter.serialize();
    const tmp = RATE_LIMITS_SNAPSHOT_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(byName), { mode: SENSITIVE_FILE_MODE });
    fs.renameSync(tmp, RATE_LIMITS_SNAPSHOT_FILE);
    logger.info('rate limiter state snapshotted for graceful restart');
  } catch (err) {
    logger.error({ err }, 'failed to snapshot rate limiter state before shutdown - usage counts will reset');
  }
}

try { fs.mkdirSync(path.dirname(RATE_LIMITS_SNAPSHOT_FILE), { recursive: true, mode: SENSITIVE_DIR_MODE }); } catch {}
loadRateLimitsSnapshot();

// ── Statistics ───────────────────────────────────────────────────────────────
const STATS_FILE = process.env.STATS_FILE || path.join(__dirname, 'data', 'stats.json');

const STATS_DEFAULTS = {
  secretsCreated:      0,
  secretsWithEmail:    0,
  emailsSent:          0,
  secretsRevealed:     0,
  secretsExpired:      0,
  secretsBruteForced:  0,
  otpFailures:         0,
};

let stats = { ...STATS_DEFAULTS };

try {
  fs.mkdirSync(path.dirname(STATS_FILE), { recursive: true, mode: SENSITIVE_DIR_MODE });
  const raw = fs.readFileSync(STATS_FILE, 'utf8');
  stats = { ...STATS_DEFAULTS, ...JSON.parse(raw) };
} catch {}

function saveStats() {
  try {
    const tmp = STATS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(stats, null, 2), { mode: SENSITIVE_FILE_MODE });
    fs.renameSync(tmp, STATS_FILE);
  } catch (err) {
    logger.error({ err }, 'failed to persist stats file');
  }
}

// Purge interval declared after stats so stats.secretsExpired is always initialised
const purge = setInterval(() => {
  const now = Date.now();
  let purged = 0;
  for (const [id, s] of secrets) {
    if (now > s.expiresAt) {
      secrets.delete(id);
      stats.secretsExpired++;
      purged++;
    }
  }
  if (purged > 0) {
    logger.info({ purged, remaining: secrets.size }, 'expired secrets purged');
  }
}, 60_000);

const statsPersist = setInterval(saveStats, 60_000);
if (purge.unref) purge.unref();
if (statsPersist.unref) statsPersist.unref();

// ── Validators ──────────────────────────────────────────────────────────────
const UUID_RE  = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const B64_RE   = /^[A-Za-z0-9+/]+=*$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
// AES-GCM IV must be 12 raw bytes → exactly 16 base-64 chars
const IV_B64_LEN  = 16;
// AES-256 key half (32 bytes) → exactly 44 base-64 chars. A SHA-256 digest
// (K1's hash, sent at both creation and reveal - K1 itself never crosses
// the network) is also 32 bytes, so this length applies to both.
const K2_B64_LEN  = 44;
// AES-GCM output is always at least 16-byte auth tag → min 24 base-64 chars
const MIN_CT_LEN      = 24;
// Max plaintext 10 KB + 16-byte GCM tag → ≤ 13 720 base-64 chars
const MAX_CT_LEN      = 13_720;
// Max file 2 MB + 16-byte GCM tag → ≤ 2 796 224 base-64 chars
const MAX_FILE_CT_LEN = 2_796_224;
// Pro: max file 25 MB + 16-byte GCM tag → ≤ 34 952 556 base-64 chars
const MAX_FILE_CT_LEN_PRO = 34_952_556;
const MAX_FILENAME_LEN = 255;

// ── Startup checks ────────────────────────────────────────────────────────────
if (process.env.CIPHER_KEY && !/^[0-9a-f]{64}$/i.test(process.env.CIPHER_KEY)) {
  logger.fatal('CIPHER_KEY must be exactly 64 hex characters (32 bytes). Exiting.');
  process.exit(1);
}

// ── Server secrets (K3 + K4) ─────────────────────────────────────────────────
// K3: masks K2 in memory via HMAC — unique per secret, tied to its ID.
// K4: re-encrypts the ciphertext at rest — mandatory for any decryption.
// Neither key ever leaves the server or travels over any network.
const K3 = process.env.SECRET_KEY;
const K4 = process.env.CIPHER_KEY ? Buffer.from(process.env.CIPHER_KEY, 'hex') : null;

function deriveK3Mask(id) {
  return crypto.createHmac('sha256', K3).update(id).digest();
}

// A plain SHA-256(otp) hash is only 1,000,000 possibilities - anyone who
// gets a secrets snapshot can brute-force every OTP in it offline in well
// under a second, no server interaction (and so no 5-attempt limit) needed.
// Keying the hash with K3, derived with domain separation so it can never
// collide with deriveK3Mask's own output, means the snapshot alone is no
// longer enough - same server secret an attacker would already need to use
// the snapshot's K2/ciphertext at all. Binding to the secret id stops two
// secrets that happen to draw the same 6-digit code from hashing identically.
const OTP_HMAC_KEY = K3 ? crypto.createHmac('sha256', K3).update('blink-otp-hmac-v1').digest() : Buffer.alloc(32);
function hashOtp(otp, id) {
  return crypto.createHmac('sha256', OTP_HMAC_KEY).update(id).update(otp).digest('hex');
}

function encryptWithK4(ciphertextB64) {
  const ct  = Buffer.from(ciphertextB64, 'base64');
  const iv  = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', K4, iv, { authTagLength: 16 });
  const enc = Buffer.concat([cipher.update(ct), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    encCt: Buffer.concat([enc, tag]).toString('base64'),
    ctIv:  iv.toString('base64'),
  };
}

function decryptWithK4(encCtB64, ctIvB64) {
  const enc = Buffer.from(encCtB64, 'base64');
  const iv  = Buffer.from(ctIvB64,  'base64');
  const tag = enc.subarray(enc.length - 16);
  const ct  = enc.subarray(0, enc.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', K4, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('base64');
}

// ── Email client ─────────────────────────────────────────────────────────────
const resendClient = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;

// ── Reveal-time key release (true end-to-end: server never decrypts) ───────
// The server never reconstructs K = K1 XOR K2 and never touches plaintext -
// AES-GCM decryption happens exclusively in the recipient's browser (see
// clientDecrypt() in public/view.js). This function's only job is deciding
// whether to release K2 at all: K2_stored = K2 XOR HMAC(K3, id) at creation
// time, so unmaskK2() reverses that (XOR is self-inverse) to recover the
// plain K2, which is still useless on its own without K1.
//
// K1 itself NEVER crosses the network at all, at creation or at reveal -
// the browser sends only SHA-256(K1) at creation (stored as secret.k1Hash)
// and again at reveal (via the X-Key-Hash header, compared directly
// against the stored one). A match proves the caller holds the real K1
// without the server ever needing to see, possess, or combine it with K2.
function unmaskK2(k2StoredB64, id) {
  const k2Stored = Buffer.from(k2StoredB64, 'base64');
  const mask     = K3 ? deriveK3Mask(id) : Buffer.alloc(32);
  const k2 = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k2[i] = k2Stored[i] ^ mask[i];
  return k2.toString('base64');
}

// ── Email (Resend) ───────────────────────────────────────────────────────────
// Last 8 hex chars of the secret's UUID — enough to eyeball-match this email
// against the tail of a specific share link, without dumping a full 36-char
// UUID into the email body. Not sensitive: it doesn't help decrypt anything.
function idFragment(id) {
  return id.slice(-8);
}

// Chrome's own behavior, not anything the extension sets deliberately: a
// fetch() from an extension's background service worker always carries
// Origin: chrome-extension://<id>, while the website's own same-origin
// requests carry Origin: https://blink.malto.icu. No CORS handling needed
// either way - this is purely for telling the two apart in logs.
function requestSource(req) {
  const origin = req.headers.origin || '';
  if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://')) return 'extension';
  if (origin) return 'web';
  return 'unknown';
}

function formatExpiry(hours) {
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'}`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? '' : 's'}`;
}

function viewsSetByLine(viewsAllowed) {
  return viewsAllowed > 1
    ? `The sender set this secret to be viewed up to ${viewsAllowed} times.`
    : 'The sender set this secret to be viewed only once.';
}

// Shared chrome for both transactional emails: logo + wordmark, a green
// eyebrow badge naming the email's type, and a fading green divider —
// mirrors the site's own light-theme tokens (style.css) and badge pattern
// (e.g. .about-hero-badge), since CSS mask-recoloring isn't available in
// email clients. The logo cell is skipped entirely when LOGO_URL isn't
// configured, rather than falling back to this deployment's own image.
function emailHeader(eyebrow) {
  const logoCell = LOGO_URL
    ? `<td style="vertical-align:middle;width:32px;"><img src="${LOGO_URL}" alt="Blink" width="32" height="32" style="display:block;height:32px;width:32px;"></td>`
    : '';
  return `
    <tr><td style="padding:24px 28px 18px;">
      <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
        ${logoCell}
        <td style="vertical-align:middle;padding-left:10px;white-space:nowrap;">
          <span style="color:#2f9e2a;font-size:18px;font-weight:700;">Blink</span>
          <span style="display:inline-block;margin-left:8px;border:1px solid rgba(0,0,0,0.10);border-radius:999px;padding:3px 9px;font-size:10px;color:#9aa0aa;vertical-align:middle;">by MALTO</span>
        </td>
        <td style="vertical-align:middle;text-align:right;">
          <span style="display:inline-block;border:1px solid rgba(97,207,90,.2);background:rgba(97,207,90,.10);border-radius:999px;padding:4px 12px;font-size:10px;font-weight:600;letter-spacing:0.08em;color:#2f9e2a;text-transform:uppercase;">${eyebrow}</span>
        </td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:0 28px;"><div style="height:1px;background:linear-gradient(90deg, rgba(255,255,255,0), rgba(97,207,90,.55), rgba(255,255,255,0));"></div></td></tr>
  `;
}

// The version/site line links to this deployment's own HOST, not a
// hardcoded domain - without HOST configured, it's still just plain text.
function emailFooter() {
  const siteLine = process.env.HOST
    ? `Blink v${APP_VERSION} &middot; <a href="https://${process.env.HOST}" style="color:#9aa0aa;text-decoration:none;">${process.env.HOST}</a>`
    : `Blink v${APP_VERSION}`;
  return `
    <tr><td style="padding:9px 28px;border-top:1px solid rgba(0,0,0,0.10);text-align:center;">
      <p style="margin:0;font-size:10px;line-height:1.3;color:#9aa0aa;">${siteLine}</p>
    </td></tr>
  `;
}

// Hidden preheader text: without it, clients fall back to showing boilerplate
// (e.g. "View in browser") as the inbox preview snippet instead of context.
function preheader(text) {
  const padding = '&#8203;'.repeat(20);
  return `<div style="display:none;max-height:0;overflow:hidden;opacity:0;mso-hide:all;">${text} ${padding}</div>`;
}

async function sendOTPEmail(to, otp, id, viewsAllowed = 1, expiresInHours = 48) {
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: '[Blink - Verification] Your Blink verification code',
    html: `
      <div style="margin:0;padding:0;background:#f5f5f5;">
        ${preheader(`Your Blink code: ${otp}. Someone shared a secret with you.`)}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;"><tr><td align="center" style="padding:36px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid rgba(0,0,0,0.10);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            ${emailHeader('Verification')}
            <tr><td style="padding:26px 28px 20px;text-align:center;">
              <p style="margin:0 0 20px;font-size:15px;color:#111111;line-height:1.5;">Someone shared a secret with you. Enter this code on the Blink page to reveal it:</p>
              <div style="background:#f0f0f0;border:1px solid rgba(0,0,0,0.10);border-top:2px solid rgba(97,207,90,.5);border-radius:10px;padding:24px 20px 18px;">
                <span style="font-family:ui-monospace,'SF Mono',Consolas,'Courier New',monospace;font-size:38px;font-weight:700;letter-spacing:9px;color:#2f9e2a;">${otp}</span>
                <div style="margin-top:10px;font-size:11px;color:#68707c;">${viewsSetByLine(viewsAllowed)} Expires in ${formatExpiry(expiresInHours)}.</div>
              </div>
              <p style="margin:16px 0 0;font-size:11px;color:#b5b9bf;line-height:1.6;">Link ...${idFragment(id)} &nbsp;&middot;&nbsp; works once &nbsp;&middot;&nbsp; didn't request it? ignore this email.</p>
            </td></tr>
            ${emailFooter()}
          </table>
        </td></tr></table>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

async function sendViewNotification(to, viewsLeft, id) {
  const remaining = viewsLeft > 0
    ? `It can be viewed ${viewsLeft} more time${viewsLeft === 1 ? '' : 's'} before it is destroyed.`
    : 'It has now been permanently deleted from the server.';
  const pill = viewsLeft > 0
    ? `<span style="display:inline-block;background:rgba(97,207,90,.10);border:1px solid rgba(97,207,90,.2);border-radius:999px;padding:7px 16px;font-size:12px;font-weight:600;color:#2f9e2a;">&#9679;&nbsp; ${viewsLeft} view${viewsLeft === 1 ? '' : 's'} left</span>`
    : `<span style="display:inline-block;background:#f0f0f0;border:1px solid rgba(0,0,0,.10);border-radius:999px;padding:7px 16px;font-size:12px;font-weight:600;color:#68707c;">&#9679;&nbsp; Deleted</span>`;
  const previewText = viewsLeft > 0
    ? 'A secret you shared was just viewed.'
    : 'A secret you shared was viewed and deleted.';
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: '[Blink - Activity] Your Blink secret was viewed',
    html: `
      <div style="margin:0;padding:0;background:#f5f5f5;">
        ${preheader(previewText)}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;"><tr><td align="center" style="padding:36px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid rgba(0,0,0,0.10);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            ${emailHeader('Activity')}
            <tr><td style="padding:26px 28px 20px;text-align:center;">
              <p style="margin:0 0 16px;font-size:15px;color:#111111;line-height:1.5;">A secret you shared on Blink was just viewed.</p>
              <div style="margin:0 0 12px;">${pill}</div>
              <p style="margin:0 0 16px;font-size:12px;color:#68707c;line-height:1.5;">${remaining}</p>
              <p style="margin:0;font-size:11px;color:#b5b9bf;line-height:1.6;">Link ...${idFragment(id)}</p>
            </td></tr>
            ${emailFooter()}
          </table>
        </td></tr></table>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

async function sendLicenseKeyEmail(to, key) {
  const { error } = await resendClient.emails.send({
    from:    process.env.EMAIL_FROM || 'Blink <noreply@malto.icu>',
    to,
    subject: '[Blink - Pro] Your Blink Pro license key',
    html: `
      <div style="margin:0;padding:0;background:#f5f5f5;">
        ${preheader(`Your Blink Pro license key: ${key}`)}
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f5f5f5;"><tr><td align="center" style="padding:36px 16px;">
          <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background:#ffffff;border:1px solid rgba(0,0,0,0.10);border-radius:10px;overflow:hidden;box-shadow:0 1px 3px rgba(0,0,0,.05);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            ${emailHeader('Pro')}
            <tr><td style="padding:26px 28px 20px;text-align:center;">
              <p style="margin:0 0 20px;font-size:15px;color:#111111;line-height:1.5;">Thanks for upgrading to Blink Pro. Sign in with Google or GitHub on the Blink site, open the Pro panel, and paste this key in to activate it on your account:</p>
              <div style="background:#f0f0f0;border:1px solid rgba(0,0,0,0.10);border-top:2px solid rgba(97,207,90,.5);border-radius:10px;padding:20px 16px;">
                <span style="font-family:ui-monospace,'SF Mono',Consolas,'Courier New',monospace;font-size:17px;font-weight:700;letter-spacing:1px;color:#2f9e2a;word-break:break-all;">${key}</span>
              </div>
              <p style="margin:16px 0 0;font-size:11px;color:#b5b9bf;line-height:1.6;">This key activates on one account at a time. Didn't subscribe? Contact support and we'll sort it out.</p>
            </td></tr>
            ${emailFooter()}
          </table>
        </td></tr></table>
      </div>
    `,
  });
  if (error) throw new Error(error.message);
}

// ── POST /api/webhooks/paddle ────────────────────────────────────────────────
// The only thing that ever issues or revokes a Blink Pro license key. Paddle
// delivers webhooks at-least-once and retries anything that doesn't answer
// 2xx within 5 seconds, so every branch below is an idempotent upsert keyed
// on Paddle's own subscription id (issueLicenseKey/updateSubscriptionStatus)
// rather than anything that could double-fire on a retried delivery. A
// signature failure and a handler error both fall through to the same
// non-2xx response on purpose — Paddle retries either way, and a rotated
// secret recovers automatically on the next attempt once redeployed; trying
// to tell "forged" apart from "broke" here would be guessing.
app.post('/api/webhooks/paddle', express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
  if (!paddleClient || !PADDLE_WEBHOOK_SECRET) {
    req.log.error('Paddle webhook received but PADDLE_API_KEY/PADDLE_WEBHOOK_SECRET is not configured');
    return res.status(503).end();
  }
  const signature = req.headers['paddle-signature'];
  const rawBody    = req.body;
  if (typeof signature !== 'string' || !Buffer.isBuffer(rawBody) || rawBody.length === 0) {
    return res.status(400).end();
  }

  let event;
  try {
    event = await paddleClient.webhooks.unmarshal(rawBody.toString('utf8'), PADDLE_WEBHOOK_SECRET, signature);
  } catch (err) {
    req.log.warn({ err: err.message }, 'Paddle webhook signature verification failed');
    return res.status(401).end();
  }
  if (!event) return res.status(200).end();

  try {
    switch (event.eventType) {
      // Fires once Paddle has actually billed the customer - unlike
      // subscription.created, which fires immediately on checkout before
      // payment is confirmed. This is the one place a key gets minted.
      case 'subscription.activated': {
        const sub = event.data;
        const customer = await paddleClient.customers.get(sub.customerId);
        const email = customer?.email || null;
        const key = issueLicenseKey(email, sub.id);
        if (email) {
          try { await sendLicenseKeyEmail(email, key); }
          catch (err) { req.log.error({ err, subscriptionId: sub.id }, 'failed to send Paddle license key email'); }
        } else {
          req.log.warn({ subscriptionId: sub.id }, 'Paddle subscription activated with no customer email on file');
        }
        req.log.info({ subscriptionId: sub.id }, 'Paddle license key issued');
        break;
      }
      case 'subscription.canceled':
        updateSubscriptionStatus(event.data.id, 'canceled');
        req.log.info({ subscriptionId: event.data.id }, 'Paddle subscription canceled');
        break;
      case 'subscription.past_due':
        updateSubscriptionStatus(event.data.id, 'past_due');
        req.log.info({ subscriptionId: event.data.id }, 'Paddle subscription past due');
        break;
      case 'subscription.updated': {
        // Paddle's own status is the single source of truth here - covers
        // e.g. a past_due subscription paying successfully and resuming.
        const sub = event.data;
        if (['active', 'trialing'].includes(sub.status)) updateSubscriptionStatus(sub.id, 'active');
        else if (sub.status === 'canceled') updateSubscriptionStatus(sub.id, 'canceled');
        else if (sub.status === 'past_due') updateSubscriptionStatus(sub.id, 'past_due');
        break;
      }
      default:
        break; // subscribed to an event we don't act on - not an error
    }
  } catch (err) {
    req.log.error({ err, eventType: event.eventType }, 'Paddle webhook handler failed');
    return res.status(500).end();
  }

  res.status(200).end();
});

// ── POST /api/license/activate ───────────────────────────────────────────────
// Requires a verified session (Google or GitHub). Binds the submitted key to
// THIS account's email — activateLicense() enforces that no other account
// can already hold the same key, the local equivalent of Lemon Squeezy's
// "Activation Limit = 1". The key is stored server-side only; the browser
// never receives it back.
app.post('/api/license/activate', createLimiter.middleware(), jsonSmall, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) {
    return res.status(401).json({ valid: false, error: 'login_required' });
  }

  const key = typeof req.body?.licenseKey === 'string' ? req.body.licenseKey.trim() : '';
  if (!LICENSE_KEY_RE.test(key)) {
    return res.json({ valid: false, error: 'invalid' });
  }

  const subHash  = session.sub;
  const existing = licenses[subHash];

  if (PRO_DEV_KEY && key === PRO_DEV_KEY) {
    licenses[subHash] = { licenseKey: key, email: session.email || null, activatedAt: Date.now() };
    saveLicenses();
    req.log.info({ account: subHash, dev: true }, 'license activated');
    return res.json({ valid: true });
  }

  // Already activated with this exact key on this account — nothing to do.
  if (existing && existing.licenseKey === key) {
    req.log.info({ account: subHash }, 'license re-activation: already active, no-op');
    return res.json({ valid: true });
  }

  // Switching to a different key: free the old slot first.
  if (existing) {
    deactivateLicense(existing.licenseKey, subHash);
    delete licenses[subHash];
    req.log.info({ account: subHash }, 'license deactivated (switching keys)');
  }

  const { ok, error } = activateLicense(key, subHash);
  if (!ok) {
    req.log.warn({ account: subHash, reason: error }, 'license activation rejected');
    return res.json({ valid: false, error });
  }
  licenses[subHash] = { licenseKey: key, email: session.email || null, activatedAt: Date.now() };
  saveLicenses();
  req.log.info({ account: subHash }, 'license activated');
  res.json({ valid: true });
});

// ── POST /api/license/deactivate ─────────────────────────────────────────────
// Frees this account's activation slot. No body needed — the server already
// knows which license belongs to this session.
app.post('/api/license/deactivate', createLimiter.middleware(), (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const session = readSession(req);
  if (!session) {
    return res.status(401).json({ ok: false });
  }
  const record = licenses[session.sub];
  if (!record) {
    return res.json({ ok: true });
  }
  delete licenses[session.sub];
  saveLicenses();
  if (!(PRO_DEV_KEY && record.licenseKey === PRO_DEV_KEY)) {
    deactivateLicense(record.licenseKey, session.sub);
  }
  req.log.info({ account: session.sub }, 'license deactivated');
  res.json({ ok: true });
});

// ── POST /api/secret ────────────────────────────────────────────────────────
app.post('/api/secret', createLimiter.middleware(), async (req, res, next) => {
  const session = readSession(req);
  req.session = session;
  req.isPro   = await isProForSession(session);
  return (req.isPro ? jsonLarge : jsonSmall)(req, res, next);
}, async (req, res) => {
  const body = req.body;
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  const {
    ciphertext, iv, k2, k1Hash, recipientEmail, expiresIn: expiresInRaw,
    isFile, filename: rawFilename, mimetype: rawMimetype,
    views: viewsRaw, passphrase: passphraseRaw, notifyEmail: notifyEmailRaw,
  } = body;

  const isPro = req.isPro === true;
  if (isPro) {
    // Bucketed by the account (already a one-way hash of its verified
    // email), not the license key — with Activation Limit = 1 the two
    // are equivalent, and this way the raw key is never touched here.
    const retryAfter = licenseUsageLimiter.check(req.session.sub);
    if (retryAfter > 0) {
      res.setHeader('Retry-After', String(retryAfter));
      req.log.warn({ limiter: 'pro-usage', account: req.session.sub, retryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: 'This license has reached its daily usage limit. Try again tomorrow, or contact support if this seems wrong.' });
    }
  } else {
    const retryAfter = freeUsageLimiter.check(req.ip);
    if (retryAfter > 0) {
      res.setHeader('Retry-After', String(retryAfter));
      req.log.warn({ limiter: 'free-usage', retryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: `Free plan is limited to ${freeUsageLimiter.max} secrets per day. Upgrade to Pro for more, or try again tomorrow.` });
    }
  }
  const isFileSecret = isFile === true;
  const maxCtLen = isFileSecret
    ? (isPro ? MAX_FILE_CT_LEN_PRO : MAX_FILE_CT_LEN)
    : MAX_CT_LEN;

  if (
    typeof ciphertext !== 'string' || typeof iv !== 'string' || typeof k2 !== 'string' || typeof k1Hash !== 'string' ||
    !ciphertext || !iv || !k2 || !k1Hash ||
    !B64_RE.test(iv) || !B64_RE.test(ciphertext) || !B64_RE.test(k2) || !B64_RE.test(k1Hash) ||
    iv.length !== IV_B64_LEN ||
    k2.length !== K2_B64_LEN ||
    k1Hash.length !== K2_B64_LEN ||
    ciphertext.length < MIN_CT_LEN ||
    ciphertext.length > maxCtLen
  ) {
    return res.status(400).json({ error: 'Invalid payload.' });
  }

  if (isFileSecret) {
    if (typeof rawFilename !== 'string' || !rawFilename.trim() || rawFilename.length > MAX_FILENAME_LEN) {
      return res.status(400).json({ error: 'Invalid filename.' });
    }
    if (typeof rawMimetype !== 'string' || !rawMimetype.trim() || rawMimetype.length > 127) {
      return res.status(400).json({ error: 'Invalid mimetype.' });
    }
  }

  if (capacityExceeded(ciphertext.length)) {
    req.log.error({ secretsInMemory: secrets.size, bytesInMemory: totalStoredCiphertextBytes() }, 'server at capacity, rejecting create');
    return res.status(503).json({ error: 'Server is at capacity. Try again shortly.' });
  }

  // Generated early so it can be embedded in the OTP email below, letting a
  // recipient with multiple pending secrets match a code to the right link.
  const id = crypto.randomUUID();

  // ── Pro-gated options ──
  let viewsAllowed = 1;
  if (viewsRaw !== undefined) {
    const v = Number(viewsRaw);
    if (!Number.isInteger(v) || v < 1 || v > MAX_VIEWS_PRO) {
      return res.status(400).json({ error: 'Invalid views value.' });
    }
    if (v > 1 && !isPro) {
      req.log.info({ feature: 'multi-view links' }, 'pro feature blocked: not a pro account');
      return res.status(403).json({ error: 'pro_required', feature: 'multi-view links' });
    }
    viewsAllowed = v;
  }

  let passHash = null;
  let passSalt = null;
  if (passphraseRaw !== undefined) {
    if (!isPro) {
      req.log.info({ feature: 'passphrase protection' }, 'pro feature blocked: not a pro account');
      return res.status(403).json({ error: 'pro_required', feature: 'passphrase protection' });
    }
    if (typeof passphraseRaw !== 'string' ||
        passphraseRaw.length < PASSPHRASE_MIN_LEN || passphraseRaw.length > PASSPHRASE_MAX_LEN) {
      return res.status(400).json({ error: `Passphrase must be ${PASSPHRASE_MIN_LEN}-${PASSPHRASE_MAX_LEN} characters.` });
    }
    passSalt = crypto.randomBytes(16);
    passHash = crypto.scryptSync(passphraseRaw, passSalt, 32);
  }

  let notifyEmail = null;
  if (notifyEmailRaw !== undefined) {
    if (!isPro) {
      req.log.info({ feature: 'view notifications' }, 'pro feature blocked: not a pro account');
      return res.status(403).json({ error: 'pro_required', feature: 'view notifications' });
    }
    if (!resendClient) {
      req.log.warn('view notification requested but RESEND_API_KEY is not configured');
      return res.status(503).json({ error: 'Email is not configured on this server.' });
    }
    if (typeof notifyEmailRaw !== 'string' || !EMAIL_RE.test(notifyEmailRaw)) {
      return res.status(400).json({ error: 'Invalid notification email address.' });
    }
    notifyEmail = notifyEmailRaw;
  }

  if (Number(expiresInRaw) === 168 && !isPro) {
    req.log.info({ feature: '7-day expiry' }, 'pro feature blocked: not a pro account');
    return res.status(403).json({ error: 'pro_required', feature: '7-day expiry' });
  }

  // Computed before the OTP email below so the email can tell the recipient
  // how long the link lasts and how many times the sender allowed it to be viewed.
  const allowedTtl = isPro ? ALLOWED_TTL_HOURS_PRO : ALLOWED_TTL_HOURS;
  const expiresInHours = allowedTtl.has(Number(expiresInRaw)) ? Number(expiresInRaw) : DEFAULT_TTL_HOURS;
  const expiresAt = Date.now() + expiresInHours * 3_600_000;

  let otpHash = null;
  if (recipientEmail !== undefined) {
    if (!resendClient) {
      req.log.warn('otp email verification requested but RESEND_API_KEY is not configured');
      return res.status(503).json({ error: 'Email verification is not configured on this server.' });
    }
    if (typeof recipientEmail !== 'string' || !EMAIL_RE.test(recipientEmail)) {
      return res.status(400).json({ error: 'Invalid email address.' });
    }
    const emailRetryAfter = emailLimiter.check(req.ip);
    if (emailRetryAfter > 0) {
      res.setHeader('Retry-After', String(emailRetryAfter));
      req.log.warn({ limiter: 'email', retryAfter: emailRetryAfter }, 'rate limit exceeded');
      return res.status(429).json({ error: 'Too many verification emails. Try again in an hour.' });
    }

    const otp = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    otpHash   = hashOtp(otp, id);
    try {
      await sendOTPEmail(recipientEmail, otp, id, viewsAllowed, expiresInHours);
      stats.emailsSent++;
      req.log.info({ secretId: idFragment(id) }, 'otp email sent');
    } catch (err) {
      req.log.error({ err, secretId: idFragment(id) }, 'failed to send otp email');
      return res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
  }

  // Apply K3 mask to K2 before storage: k2Stored = K2 XOR HMAC(K3, id)
  let k2Stored = k2;
  if (K3) {
    const mask     = deriveK3Mask(id);
    const k2Buf    = Buffer.from(k2, 'base64');
    const maskedBuf = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) maskedBuf[i] = k2Buf[i] ^ mask[i];
    k2Stored = maskedBuf.toString('base64');
  }

  // Wrap ciphertext with K4 before storage — K4 is mandatory for any decryption
  let storedCt = ciphertext;
  let ctIv     = null;
  if (K4) {
    ({ encCt: storedCt, ctIv } = encryptWithK4(ciphertext));
  }

  // Re-checked here, after the only await in this handler (the OTP email
  // send above) - see capacityExceeded()'s comment. A reject at this point
  // is rarer and means an OTP email may already be in the recipient's inbox
  // for a secret that was never stored; logged distinctly so that's visible.
  if (capacityExceeded(ciphertext.length)) {
    req.log.error({ secretsInMemory: secrets.size, bytesInMemory: totalStoredCiphertextBytes() }, 'server reached capacity while this create request was in flight, rejecting');
    return res.status(503).json({ error: 'Server is at capacity. Try again shortly.' });
  }

  const filename = isFileSecret ? rawFilename.trim() : null;
  const mimetype = isFileSecret ? rawMimetype.trim() : null;
  secrets.set(id, {
    ciphertext: storedCt, ctIv, iv, k2: k2Stored, k1Hash, expiresAt,
    otpHash, otpAttempts: 0,
    isFile: isFileSecret, filename, mimetype,
    viewsLeft: viewsAllowed,
    passHash: passHash ? passHash.toString('hex') : null,
    passSalt: passSalt ? passSalt.toString('hex') : null,
    passAttempts: 0,
    notifyEmail,
  });

  stats.secretsCreated++;
  if (otpHash) stats.secretsWithEmail++;

  req.log.info({
    secretId:    idFragment(id),
    source:      requestSource(req),
    isPro,
    isFile:      isFileSecret,
    viewsAllowed,
    expiresInHours,
    hasOtp:      !!otpHash,
    hasPassphrase: !!passHash,
    hasNotify:   !!notifyEmail,
  }, 'secret created');

  res.status(201).json({ id });
});

// ── GET /api/secret/:id ─────────────────────────────────────────────────────
app.get('/api/secret/:id', readLimiter.middleware(), (req, res) => {
  const { id } = req.params;

  if (!UUID_RE.test(id)) {
    return res.status(400).json({ error: 'Invalid identifier.' });
  }

  // This is SHA-256(K1), not K1 itself - K1 never crosses the network at
  // all, at creation or at reveal, only this one-way hash of it does. See
  // the big comment above unmaskK2() for the full reasoning.
  const k1HashHeader = (req.headers['x-key-hash'] || '').trim();
  if (!k1HashHeader || k1HashHeader.length !== K2_B64_LEN || !B64_RE.test(k1HashHeader)) {
    return res.status(400).json({ error: 'Missing or invalid key.' });
  }

  res.setHeader('Cache-Control', 'no-store');

  const secret = secrets.get(id);
  if (!secret) {
    req.log.debug({ secretId: idFragment(id) }, 'secret not found (already viewed, expired, or never existed)');
    return res.status(404).json({ error: 'not_found' });
  }

  if (Date.now() > secret.expiresAt) {
    secrets.delete(id);
    req.log.info({ secretId: idFragment(id) }, 'secret access attempted after expiry');
    return res.status(410).json({ error: 'expired' });
  }

  // A secret created by a server process from before this field existed
  // (restored from a graceful-restart snapshot across a deploy) has no
  // k1Hash to check against - treat it the same as "gone" rather than
  // crash on a missing field.
  if (!secret.k1Hash) {
    secrets.delete(id);
    req.log.warn({ secretId: idFragment(id) }, 'secret predates k1Hash support, discarding');
    return res.status(410).json({ error: 'expired' });
  }

  // Verify the caller holds the real K1 - purely by comparing the supplied
  // hash to the one recorded at creation, no decrypt attempt, no K1 or K
  // ever constructed - before touching the passphrase/OTP gates or burning
  // an attempt against them. This must run before any other gate: an
  // attacker who only knows a secret's UUID, but not its key, must never be
  // able to spend down the passphrase/OTP attempt counters and get the
  // secret destroyed without ever proving key possession. See the big
  // comment above unmaskK2() for why the hash comparison alone is enough.
  const suppliedHash = Buffer.from(k1HashHeader, 'base64');
  const storedHash   = Buffer.from(secret.k1Hash, 'base64');
  if (suppliedHash.length !== storedHash.length || !crypto.timingSafeEqual(suppliedHash, storedHash)) {
    req.log.warn({ secretId: idFragment(id) }, 'reveal rejected: wrong key');
    return res.status(400).json({ error: 'Invalid key. The link may be corrupted.' });
  }

  // Passphrase verification (Pro)
  if (secret.passHash) {
    const rawHeader = (req.headers['x-passphrase'] || '').trim();
    if (!rawHeader) {
      req.log.debug({ secretId: idFragment(id) }, 'passphrase required, not yet supplied');
      return res.status(403).json({ error: 'passphrase_required' });
    }
    let pass = '';
    try { pass = decodeURIComponent(rawHeader); } catch { pass = rawHeader; }
    const inputHash = crypto.scryptSync(
      pass.slice(0, PASSPHRASE_MAX_LEN),
      Buffer.from(secret.passSalt, 'hex'),
      32
    );
    const passValid = crypto.timingSafeEqual(Buffer.from(secret.passHash, 'hex'), inputHash);
    if (!passValid) {
      secret.passAttempts++;
      if (secret.passAttempts >= MAX_AUTH_ATTEMPTS) {
        secrets.delete(id);
        stats.secretsBruteForced++;
        req.log.warn({ secretId: idFragment(id) }, 'secret destroyed: too many passphrase attempts');
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      req.log.warn({ secretId: idFragment(id), attemptsLeft: MAX_AUTH_ATTEMPTS - secret.passAttempts }, 'invalid passphrase attempt');
      return res.status(403).json({ error: 'invalid_passphrase', attemptsLeft: MAX_AUTH_ATTEMPTS - secret.passAttempts });
    }
  }

  // OTP verification
  if (secret.otpHash) {
    const otp = (req.headers['x-otp'] || '').trim();
    if (!otp) {
      req.log.debug({ secretId: idFragment(id) }, 'otp required, not yet supplied');
      return res.status(403).json({ error: 'otp_required' });
    }
    if (!/^\d{6}$/.test(otp)) {
      return res.status(403).json({ error: 'invalid_otp' });
    }
    const inputHash = hashOtp(otp, id);
    const valid     = crypto.timingSafeEqual(
      Buffer.from(secret.otpHash, 'hex'),
      Buffer.from(inputHash,      'hex')
    );
    if (!valid) {
      secret.otpAttempts++;
      stats.otpFailures++;
      if (secret.otpAttempts >= 5) {
        secrets.delete(id);
        stats.secretsBruteForced++;
        req.log.warn({ secretId: idFragment(id) }, 'secret destroyed: too many otp attempts');
        return res.status(410).json({ error: 'too_many_attempts' });
      }
      req.log.warn({ secretId: idFragment(id), attemptsLeft: 5 - secret.otpAttempts }, 'invalid otp attempt');
      return res.status(403).json({ error: 'invalid_otp', attemptsLeft: 5 - secret.otpAttempts });
    }
  }

  // Unwrap ciphertext from K4 and unmask K2 from K3 - both are server-only
  // at-rest protections, unrelated to the AES-GCM key itself. The actual
  // decrypt happens only in the recipient's browser, which already holds
  // K1 and now receives K2 to combine with it.
  let rawCt;
  try {
    rawCt = (K4 && secret.ctIv) ? decryptWithK4(secret.ciphertext, secret.ctIv) : secret.ciphertext;
  } catch (err) {
    req.log.error({ err, secretId: idFragment(id) }, 'failed to unwrap stored ciphertext');
    return res.status(500).json({ error: 'Internal server error.' });
  }
  const k2 = unmaskK2(secret.k2, id);

  const payload = secret.isFile
    ? { ciphertext: rawCt, iv: secret.iv, k2, isFile: true, filename: secret.filename, mimetype: secret.mimetype }
    : { ciphertext: rawCt, iv: secret.iv, k2, isFile: false };

  // Multi-view (Pro): only destroy once all allowed views are consumed
  secret.viewsLeft = (secret.viewsLeft ?? 1) - 1;
  const viewsLeft = secret.viewsLeft;
  if (viewsLeft <= 0) {
    secrets.delete(id);
  }
  stats.secretsRevealed++;
  req.log.info({ secretId: idFragment(id), viewsLeft, destroyed: viewsLeft <= 0 }, 'secret viewed');

  if (secret.notifyEmail && resendClient) {
    sendViewNotification(secret.notifyEmail, viewsLeft, id)
      .then(() => { stats.emailsSent++; })
      .catch(err => req.log.error({ err, secretId: idFragment(id) }, 'failed to send view notification email'));
  }

  payload.viewsLeft = viewsLeft;
  res.json(payload);
});

// ── GET /api/config ──────────────────────────────────────────────────────────
// Public frontend configuration. The client-side token is not a secret - it
// can only open a Paddle checkout, never read account data or move money on
// its own (that needs PADDLE_API_KEY, which never leaves the server). Env
// keeps it configurable per deployment.
app.get('/api/config', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    paddleClientToken: process.env.PADDLE_CLIENT_TOKEN || null,
    paddlePriceId:     process.env.PADDLE_PRICE_ID     || null,
    paddleEnv:         process.env.PADDLE_ENV          || 'production',
    version: APP_VERSION,
  });
});

// ── GET /api/stats ───────────────────────────────────────────────────────────
app.get('/api/stats', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({ secretsCreated: stats.secretsCreated });
});

// ── About page ───────────────────────────────────────────────────────────────
app.get('/about', readLimiter.middleware(), (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'about.html'));
});

// ── Privacy policy page ────────────────────────────────────────────────────
app.get('/privacy', readLimiter.middleware(), (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'privacy.html'));
});

// ── Changelog page ─────────────────────────────────────────────────────────
app.get('/changelog', readLimiter.middleware(), (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'changelog.html'));
});

// ── View page ────────────────────────────────────────────────────────────────
app.get('/view/:id', readLimiter.middleware(), (req, res) => {
  if (!UUID_RE.test(req.params.id)) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', 'view.html'));
});

// ── 404 ─────────────────────────────────────────────────────────────────────
app.use((req, res) => {
  req.log.debug('no route matched (unknown path or scan)');
  res.status(404).json({ error: 'Not found.' });
});

// ── Global error handler ────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.type === 'entity.too.large' || err.status === 413) {
    req.log.warn({ contentLength: req.headers['content-length'] }, 'request rejected: payload too large');
    return res.status(413).json({ error: 'Payload too large.' });
  }
  if (err.status && err.status >= 400 && err.status < 500) {
    req.log.warn({ err, status: err.status }, 'request rejected: malformed');
    return res.status(err.status).json({ error: 'Invalid request.' });
  }
  req.log.error({ err }, 'unhandled request error');
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Startup checks ────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  // K3/K4 are the only thing standing between a leaked snapshot and usable
  // K2/ciphertext (see the comment above K3/K4's declaration) - silently
  // running without them in production would contradict that guarantee, so
  // this is fatal there instead of a warning. Non-production stays a warning
  // so local dev/CI doesn't need either key set.
  if (!process.env.SECRET_KEY) {
    if (process.env.NODE_ENV === 'production') {
      logger.fatal('SECRET_KEY not set: required in production for K3 HMAC binding. Exiting.');
      process.exit(1);
    }
    logger.warn('SECRET_KEY not set: K3 HMAC binding is disabled (K2 stored unmasked)');
  }
  if (!process.env.CIPHER_KEY) {
    if (process.env.NODE_ENV === 'production') {
      logger.fatal('CIPHER_KEY not set: required in production for K4 ciphertext encryption. Exiting.');
      process.exit(1);
    }
    logger.warn('CIPHER_KEY not set: K4 ciphertext encryption is disabled');
  }
  if (!process.env.RESEND_API_KEY) {
    logger.warn('RESEND_API_KEY not set: email OTP feature is disabled');
  }
  if (!process.env.PADDLE_API_KEY || !process.env.PADDLE_WEBHOOK_SECRET) {
    logger.warn('PADDLE_API_KEY / PADDLE_WEBHOOK_SECRET not set: Paddle webhook disabled, Pro effectively limited to BLINK_PRO_DEV_KEY');
  }
  if (!GOOGLE_AUTH_CONFIGURED) {
    logger.warn('Google sign-in not fully configured (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET/GOOGLE_REDIRECT_URI/SESSION_SECRET): Google Pro sign-in is disabled');
  }
  if (!GITHUB_AUTH_CONFIGURED) {
    logger.warn('GitHub sign-in not fully configured (GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET/GITHUB_REDIRECT_URI/SESSION_SECRET): GitHub Pro sign-in is disabled');
  }
  if (!GOOGLE_AUTH_CONFIGURED && !GITHUB_AUTH_CONFIGURED) {
    logger.warn('No Pro sign-in provider configured: only BLINK_PRO_DEV_KEY dev-login works locally');
  }
  if (process.env.NODE_ENV === 'production' && !process.env.HOST) {
    logger.warn('HOST not set: HTTPS redirect will not work in production');
  }
}

// ── Start ────────────────────────────────────────────────────────────────────
if (require.main === module) {
  const PORT   = parseInt(process.env.PORT || '3000', 10);
  const server = app.listen(PORT, () => {
    logger.info({ port: PORT, env: process.env.NODE_ENV || 'development', logsDir: LOGS_DIR }, 'Blink listening');
  });

  // ── Graceful shutdown ────────────────────────────────────────────────────────
  // process.exit() never waits for pending disk I/O, so logging right before
  // it is not enough on its own — flushLogs() must be awaited first, or the
  // "shutting down" line (and anything just before it) can be lost exactly
  // when it matters most. The 5s timer is the absolute last-resort kill if
  // something above hangs; flushLogs()'s own 2s internal timeout keeps it
  // from ever being what causes that.
  const shutdown = (signal) => {
    logger.info({ signal }, 'shutting down');
    saveStats();
    server.close(() => {
      saveSecretsSnapshot();
      saveRateLimitsSnapshot();
      secrets.clear();
      flushLogs().then(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 5_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
}

// Test-only hooks: the snapshot save functions are normally only reached via
// the SIGTERM/SIGINT handlers above, which real signals can't reliably drive
// in an automated test (Windows in particular doesn't deliver SIGTERM to a
// child process the way POSIX does). Exporting them lets tests exercise the
// exact save path directly, then simulate a restart by re-requiring the
// module against the same snapshot file. No behavior change for production.
module.exports = { app, saveSecretsSnapshot, saveRateLimitsSnapshot, secrets, allRateLimiters };
