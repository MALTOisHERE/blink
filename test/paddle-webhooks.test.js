'use strict';

// ── Paddle webhooks: licensing fulfillment ──────────────────────────────────
// Paddle has no hosted license-key API, so POST /api/webhooks/paddle is the
// only thing that ever issues or revokes a Blink Pro key (see server.js's
// "Blink Pro licensing" section). This drives that route with real,
// correctly HMAC-signed payloads - the same construction Paddle itself
// uses - rather than mocking paddleClient.webhooks.unmarshal, so a change to
// the signing scheme would actually be caught here.
const http   = require('node:http');
const crypto = require('node:crypto');

let lastLicenseKey = null;
const mockResend = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    const match = body.match(/Your Blink Pro license key: (BLINK-[A-Z0-9-]+)/);
    if (match) lastLicenseKey = match[1];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'mock-email-id' }));
  });
});
const MOCK_RESEND_PORT = 39741; // clear of Windows' Hyper-V excluded port ranges - see otp.test.js
mockResend.listen(MOCK_RESEND_PORT, '127.0.0.1');

process.env.NODE_ENV             = 'test';
process.env.SECRET_KEY           = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY            = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET       = 'test-session-secret';
process.env.RESEND_API_KEY       = 'test-resend-key';
process.env.RESEND_BASE_URL      = `http://127.0.0.1:${MOCK_RESEND_PORT}`;
process.env.GOOGLE_CLIENT_ID     = 'google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'google-client-secret';
process.env.GOOGLE_REDIRECT_URI  = 'https://blink.example.com/api/auth/google/callback';
process.env.PADDLE_API_KEY       = 'test-paddle-api-key';
process.env.PADDLE_ENV           = 'sandbox';
process.env.PADDLE_WEBHOOK_SECRET = 'whsec_test_secret_1234567890';
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';
process.env.LICENSES_FILE        = require('node:path').join(__dirname, '.tmp-licenses-paddle-webhooks.json');
process.env.PADDLE_LICENSES_FILE = require('node:path').join(__dirname, '.tmp-paddle-licenses-paddle-webhooks.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app }                  = require('../server');

const realFetch = global.fetch;
after(() => {
  mockResend.close();
  global.fetch = realFetch;
  for (const f of [process.env.LICENSES_FILE, process.env.PADDLE_LICENSES_FILE]) {
    try { fs.unlinkSync(f); } catch {}
  }
});

// customerId -> email, consulted by the mocked Paddle customers.get() call below.
const customerEmails = { ctm_buyer01: 'buyer@example.com', ctm_other01: 'other@example.com' };

global.fetch = async (url, options = {}) => {
  const u = String(url);
  if (u.startsWith('https://oauth2.googleapis.com/tokeninfo')) {
    const email = u.includes('other') ? 'other@example.com' : 'buyer@example.com';
    return { ok: true, json: async () => ({ aud: 'google-client-id', email_verified: 'true', email, sub: `g-${email}`, iss: 'https://accounts.google.com', exp: Math.floor(Date.now() / 1000) + 300 }) };
  }
  if (u.startsWith('https://oauth2.googleapis.com/token')) {
    // The fake id_token's payload segment encodes which account this is -
    // tokeninfo (above) decides the email from it, Google-OAuth-flow style.
    const email = String(options.body).includes('other') ? 'other@example.com' : 'buyer@example.com';
    return { ok: true, json: async () => ({ id_token: `fake.${email}.token` }) };
  }
  if (u.startsWith('https://sandbox-api.paddle.com/customers/')) {
    const customerId = u.split('/').pop();
    const email = customerEmails[customerId] || null;
    return {
      ok: true, status: 200, headers: { get: () => null },
      text: async () => JSON.stringify({ data: { id: customerId, email } }),
    };
  }
  // Everything else - notably Resend's own HTTP call to the mock server
  // above - goes through the real fetch; this override only needs to
  // intercept the two third-party APIs this test drives directly.
  return realFetch(url, options);
};

function signPaddleBody(secret, body) {
  const ts = Math.floor(Date.now() / 1000);
  const h1 = crypto.createHmac('sha256', secret).update(`${ts}:${body}`).digest('hex');
  return `ts=${ts};h1=${h1}`;
}

function subscriptionEventBody(eventType, { id, status, customerId }) {
  const now = new Date().toISOString();
  return JSON.stringify({
    event_id:        `evt_${id}_${eventType}_${Date.now()}`,
    event_type:       eventType,
    occurred_at:       now,
    notification_id: 'ntf_test',
    data: {
      id, status,
      customer_id:      customerId,
      address_id:      'add_test',
      currency_code:   'USD',
      created_at:        now,
      updated_at:        now,
      started_at:        now,
      first_billed_at:   now,
      next_billed_at:    new Date(Date.now() + 2_592_000_000).toISOString(),
      collection_mode: 'automatic',
      billing_cycle:   { interval: 'month', frequency: 1 },
      items:           [],
      custom_data:      null,
    },
  });
}

async function postWebhook(body, signature) {
  const req = request(app).post('/api/webhooks/paddle').set('Content-Type', 'application/json');
  if (signature !== undefined) req.set('Paddle-Signature', signature);
  return req.send(body);
}

// Logs in via the real Google OAuth callback path (mocked token exchange),
// exactly like oauth-success.test.js - not a hand-rolled session, so this
// exercises the same cookie this app actually issues.
async function googleLogin(email) {
  const agent = request.agent(app);
  const start = await agent.get('/api/auth/google/start');
  const stateCookie = start.headers['set-cookie'].find(c => c.startsWith('blink_oauth_state_google='));
  const state = stateCookie.split('=')[1].split(';')[0];
  const code = email.startsWith('other') ? 'other-code' : 'buyer-code';
  await agent.get(`/api/auth/google/callback?code=${code}&state=${state}`);
  return agent;
}

describe('POST /api/webhooks/paddle', () => {
  test('rejects a request with no signature header', async () => {
    const body = subscriptionEventBody('subscription.activated', { id: 'sub_nosig', status: 'active', customerId: 'ctm_buyer01' });
    const res = await postWebhook(body);
    assert.equal(res.status, 400);
  });

  test('rejects a request with a bad signature', async () => {
    const body = subscriptionEventBody('subscription.activated', { id: 'sub_badsig', status: 'active', customerId: 'ctm_buyer01' });
    const res = await postWebhook(body, 'ts=1700000000;h1=0000000000000000000000000000000000000000000000000000000000000000');
    assert.equal(res.status, 401);
  });

  test('subscription.activated issues a license key by email, which activates on that account', async () => {
    lastLicenseKey = null;
    const body = subscriptionEventBody('subscription.activated', { id: 'sub_01', status: 'active', customerId: 'ctm_buyer01' });
    const res = await postWebhook(body, signPaddleBody(process.env.PADDLE_WEBHOOK_SECRET, body));
    assert.equal(res.status, 200);

    // sendLicenseKeyEmail() goes through the real Resend client - the mock
    // server above captured the key from the actual email body.
    assert.match(lastLicenseKey, /^BLINK-[A-Z0-9-]+$/);

    const agent = await googleLogin('buyer@example.com');
    const activate = await agent.post('/api/license/activate').send({ licenseKey: lastLicenseKey });
    assert.equal(activate.body.valid, true);
    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.isPro, true);
  });

  test('a retried subscription.activated for the same subscription re-sends the same key, not a new one', async () => {
    lastLicenseKey = null;
    const body = subscriptionEventBody('subscription.activated', { id: 'sub_01', status: 'active', customerId: 'ctm_buyer01' });
    const res = await postWebhook(body, signPaddleBody(process.env.PADDLE_WEBHOOK_SECRET, body));
    assert.equal(res.status, 200);
    assert.match(lastLicenseKey, /^BLINK-[A-Z0-9-]+$/);

    const agent = await googleLogin('buyer@example.com');
    const activate = await agent.post('/api/license/activate').send({ licenseKey: lastLicenseKey });
    assert.equal(activate.body.valid, true, 'the re-issued key must be the same one already bound to this account');
  });

  test('a key already bound to one account is rejected for a different account', async () => {
    const key = lastLicenseKey; // from the previous test, still bound to buyer@example.com
    const otherAgent = await googleLogin('other@example.com');
    const activate = await otherAgent.post('/api/license/activate').send({ licenseKey: key });
    assert.equal(activate.body.valid, false);
    assert.equal(activate.body.error, 'activation_limit');
  });

  test('subscription.canceled revokes Pro for the account holding that key', async () => {
    const buyerAgent = await googleLogin('buyer@example.com');
    assert.equal((await buyerAgent.get('/api/auth/me')).body.isPro, true, 'sanity check: still Pro before cancellation');

    const body = subscriptionEventBody('subscription.canceled', { id: 'sub_01', status: 'canceled', customerId: 'ctm_buyer01' });
    const res = await postWebhook(body, signPaddleBody(process.env.PADDLE_WEBHOOK_SECRET, body));
    assert.equal(res.status, 200);

    assert.equal((await buyerAgent.get('/api/auth/me')).body.isPro, false);
  });
});
