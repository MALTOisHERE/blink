'use strict';

// ── Characterization tests: POST /api/secret's two capacity checks ─────────
// Pins the behavior fixed in "close TOCTOU race in secret-creation capacity
// checks" - a dedicated module instance with a tiny MAX_SECRETS_BYTES so both
// the early (pre-processing) and late (post-OTP-await) checks are each
// independently reachable and distinguishable.

const http = require('node:http');

const mockResend = http.createServer((req, res) => {
  req.on('data', () => {});
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ id: 'mock-email-id' }));
  });
});
const MOCK_RESEND_PORT = 39542; // outside the Hyper-V/WSL excluded range that bit otp.test.js
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
// Small enough that one real secret's ciphertext + the 512-byte per-secret
// overhead margin is close to the ceiling, but not so small the early check
// fires before a payload can even be constructed.
process.env.MAX_SECRETS_BYTES = '2000';

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const crypto                    = require('node:crypto');
const request                   = require('supertest');
const { app, secrets }         = require('../server');

after(() => { mockResend.close(); });

function sha256B64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
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
    ciphertext: Buffer.concat([enc, tag]).toString('base64'),
    iv:         iv.toString('base64'),
    k2:         k2.toString('base64'),
    k1Hash:     sha256B64(k1),
  };
}

describe('POST /api/secret: capacity checks', () => {
  test('the early check rejects a create when the store is already over budget', async () => {
    secrets.set('filler-already-over-budget', { ciphertext: 'X'.repeat(3000) });
    try {
      const res = await request(app).post('/api/secret').send(makePayload());
      assert.equal(res.status, 503);
      assert.equal(res.body.error, 'Server is at capacity. Try again shortly.');
    } finally {
      secrets.delete('filler-already-over-budget');
    }
  });

  test('the late check rejects a create that only goes over budget during the OTP email send', async () => {
    // Nothing in the store yet - the early check passes. While this request
    // is awaiting the (mocked) OTP email send, something else fills the
    // store past budget - the late re-check must catch that, even though
    // the early check already let the request through.
    mockResend.once('request', () => {
      secrets.set('filler-added-mid-request', { ciphertext: 'X'.repeat(3000) });
    });
    try {
      const res = await request(app).post('/api/secret').send({ ...makePayload(), recipientEmail: 'recipient@example.com' });
      assert.equal(res.status, 503);
      assert.equal(res.body.error, 'Server is at capacity. Try again shortly.');
    } finally {
      secrets.delete('filler-added-mid-request');
    }
  });
});
