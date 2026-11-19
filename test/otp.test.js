'use strict';

// ── Email OTP: creation + reveal (full flow) ────────────────────────────────
// Create and reveal flows for the email-OTP gate, including a real success
// case - the mock Resend server below captures the actual generated code
// from the sent email's body, so this isn't just testing failure paths -
// plus the 5-attempt lockout. otp-unconfigured.test.js covers the 503 case.

const http = require('node:http');

// A fake Resend API so OTP emails "send" successfully without a real network
// call or a real API key. The `resend` package reads RESEND_BASE_URL once at
// module load, so this must be listening and the env var set before
// `require('../server')` pulls it in.
let lastOtpSent = null;
const mockResend = http.createServer((req, res) => {
  let body = '';
  req.on('data', (chunk) => { body += chunk; });
  req.on('end', () => {
    const match = body.match(/Your Blink code: (\d{6})\./);
    if (match) lastOtpSent = match[1];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'mock-email-id' }));
  });
});
const MOCK_RESEND_PORT = 58731;
mockResend.listen(MOCK_RESEND_PORT, '127.0.0.1');

process.env.NODE_ENV           = 'test';
process.env.SECRET_KEY         = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY         = 'deadbeef'.repeat(8);
process.env.RESEND_API_KEY     = 'test-resend-key';
process.env.RESEND_BASE_URL    = `http://127.0.0.1:${MOCK_RESEND_PORT}`;
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';
process.env.EMAIL_RATE_LIMIT      = '1000';

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => { mockResend.close(); });

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

// Mirrors clientDecrypt() in public/view.js - the server never decrypts.
function clientDecrypt(ciphertextB64, ivB64, k1B64, k2B64) {
  const k1  = Buffer.from(k1B64, 'base64');
  const k2  = Buffer.from(k2B64, 'base64');
  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = k1[i] ^ k2[i];
  const ctWithTag = Buffer.from(ciphertextB64, 'base64');
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const ct  = ctWithTag.subarray(0, ctWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

describe('Email OTP: creation', () => {
  test('rejects an invalid email address', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'not-an-email' });
    assert.equal(res.status, 400);
  });

  test('creates an OTP-gated secret for a valid email, free accounts included', async () => {
    const { payload } = makePayload();
    const res = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    assert.equal(res.status, 201);
  });
});

describe('Email OTP: reveal', () => {
  test('correct OTP (captured from the mock email send) decrypts the secret', async () => {
    const { payload, k1, plaintext } = makePayload('otp protected, real code');
    lastOtpSent = null;
    const createRes = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    assert.equal(createRes.status, 201);
    assert.ok(/^\d{6}$/.test(lastOtpSent), 'mock Resend server should have captured a 6-digit OTP');
    const { id } = createRes.body;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1)).set('X-Otp', lastOtpSent);
    assert.equal(res.status, 200);
    assert.equal(clientDecrypt(res.body.ciphertext, res.body.iv, k1, res.body.k2), plaintext);
  });

  test('requires an OTP before revealing', async () => {
    const { payload, k1 } = makePayload('otp protected');
    const createRes = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    const { id } = createRes.body;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1));
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'otp_required');
  });

  test('rejects a malformed (non-6-digit) OTP', async () => {
    const { payload, k1 } = makePayload('otp protected');
    const createRes = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    const { id } = createRes.body;

    const res = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1)).set('X-Otp', 'abc');
    assert.equal(res.status, 403);
    assert.equal(res.body.error, 'invalid_otp');
  });

  test('destroys the secret after 5 wrong OTP attempts', async () => {
    const { payload, k1 } = makePayload('otp protected');
    const createRes = await request(app).post('/api/secret').send({ ...payload, recipientEmail: 'friend@example.com' });
    const { id } = createRes.body;

    let last;
    for (let i = 0; i < 5; i++) {
      last = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1)).set('X-Otp', '000000');
    }
    assert.equal(last.status, 410);
    assert.equal(last.body.error, 'too_many_attempts');

    const after = await request(app).get(`/api/secret/${id}`).set('X-Key-Hash', hashK1Header(k1)).set('X-Otp', '111111');
    assert.equal(after.status, 404);
  });
});
