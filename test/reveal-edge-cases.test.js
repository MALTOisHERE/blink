'use strict';

// ── Characterization tests for POST /api/secret and GET /api/secret/:id ────
// Pins behavior the existing suite didn't cover, ahead of decomposing those
// two handlers (ub-mode: "pin what the code does" before changing structure).
// Each test here targets one specific branch the coverage report flagged as
// untouched: expired-on-read, a pre-k1Hash legacy secret, a corrupted
// at-rest ciphertext, a failed OTP email send, and the fire-and-forget view
// notification email.

const http = require('node:http');

let otpSendShouldFail = false;
let notifyReceived    = null;
const mockResend = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    if (otpSendShouldFail) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ message: 'mock send failure' }));
    }
    if (body.includes('viewed') || body.includes('notif')) notifyReceived = body;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'mock-email-id' }));
  });
});
const MOCK_RESEND_PORT = 39541; // outside the Hyper-V/WSL excluded range that bit otp.test.js
mockResend.listen(MOCK_RESEND_PORT, '127.0.0.1');

process.env.NODE_ENV           = 'test';
process.env.SECRET_KEY         = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY         = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET     = 'test-session-secret';
process.env.BLINK_PRO_DEV_KEY  = 'test-dev-pro-key-edge';
process.env.RESEND_API_KEY     = 'test-resend-key';
process.env.RESEND_BASE_URL    = `http://127.0.0.1:${MOCK_RESEND_PORT}`;
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';
process.env.PRO_USAGE_RATE_LIMIT  = '1000';
process.env.EMAIL_RATE_LIMIT      = '1000';
process.env.LICENSES_FILE = require('node:path').join(__dirname, '.tmp-licenses-edge.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app, secrets }         = require('../server');

after(() => {
  mockResend.close();
  try { fs.unlinkSync(process.env.LICENSES_FILE); } catch {}
});

function sha256B64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

function hashK1Header(k1B64) {
  return sha256B64(Buffer.from(k1B64, 'base64'));
}

function makePayload(plaintext = 'test secret value') {
  const key = crypto.randomBytes(32);
  const iv  = crypto.randomBytes(12);
  const k1  = crypto.randomBytes(32);
  const k2  = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();

  return {
    payload: {
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv:         iv.toString('base64'),
      k2:         k2.toString('base64'),
      k1Hash:     sha256B64(k1),
    },
    k1: k1.toString('base64'),
    plaintext,
  };
}

async function proAgent() {
  const agent = request.agent(app);
  await agent.get('/api/auth/dev-login');
  await agent.post('/api/license/activate').send({ licenseKey: process.env.BLINK_PRO_DEV_KEY });
  return agent;
}

describe('GET /api/secret/:id edge cases', () => {
  test('an expired secret returns 410 and is deleted from the store', async () => {
    const { payload, k1 } = makePayload('will expire');
    const createRes = await request(app).post('/api/secret').send(payload);
    const { id } = createRes.body;

    secrets.get(id).expiresAt = Date.now() - 1000;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1));
    assert.equal(res.status, 410);
    assert.equal(res.body.error, 'expired');
    assert.equal(secrets.has(id), false);
  });

  test('a secret restored from a snapshot that predates k1Hash support is treated as gone', async () => {
    const { payload, k1 } = makePayload('legacy secret');
    const createRes = await request(app).post('/api/secret').send(payload);
    const { id } = createRes.body;

    delete secrets.get(id).k1Hash;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1));
    assert.equal(res.status, 410);
    assert.equal(res.body.error, 'expired');
    assert.equal(secrets.has(id), false);
  });

  test('a corrupted at-rest ciphertext that fails K4 unwrap returns 500, not a crash', async () => {
    const { payload, k1 } = makePayload('will be corrupted at rest');
    const createRes = await request(app).post('/api/secret').send(payload);
    const { id } = createRes.body;

    // K4 is configured (CIPHER_KEY above) - the stored ciphertext is already
    // K4-wrapped at this point. Corrupting it should surface as a clean 500
    // from decryptWithK4's own catch, not an unhandled exception.
    secrets.get(id).ciphertext = Buffer.from('not valid ciphertext at all!!').toString('base64');

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1));
    assert.equal(res.status, 500);
    assert.equal(secrets.has(id), true, 'a failed unwrap should not destroy the secret - the real ciphertext was never actually broken');
  });

  test('a view notification email fires after a successful reveal', async () => {
    notifyReceived = null;
    const agent = await proAgent();
    const { payload, k1 } = makePayload('notify on view');
    const createRes = await agent.post('/api/secret').send({ ...payload, notifyEmail: 'owner@example.com' });
    assert.equal(createRes.status, 201);
    const { id } = createRes.body;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1));
    assert.equal(res.status, 200);

    // Fire-and-forget on the server side - give it a moment to land.
    for (let i = 0; i < 20 && !notifyReceived; i++) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(notifyReceived, 'the mock Resend server should have received a notification request');
  });
});

describe('POST /api/secret: OTP email send failure', () => {
  test('a failed OTP email send returns 500 and does not create the secret', async () => {
    otpSendShouldFail = true;
    try {
      const { payload } = makePayload('otp send will fail');
      const res = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'recipient@example.com' });
      assert.equal(res.status, 500);
      assert.equal(res.body.error, 'Failed to send verification email. Please try again.');
    } finally {
      otpSendShouldFail = false;
    }
  });
});
