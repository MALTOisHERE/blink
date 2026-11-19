'use strict';

// ── File secrets ─────────────────────────────────────────────────────────────
// The isFile payload path on POST /api/secret and GET /api/secret/:id:
// filename/mimetype validation and the create-then-reveal round trip
// returning the original bytes intact.
process.env.NODE_ENV           = 'test';
process.env.SECRET_KEY         = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY         = 'deadbeef'.repeat(8);
process.env.CREATE_RATE_LIMIT     = '1000';
process.env.READ_RATE_LIMIT       = '1000';
process.env.FREE_USAGE_RATE_LIMIT = '1000';

const { describe, test } = require('node:test');
const assert             = require('node:assert/strict');
const crypto             = require('node:crypto');
const request            = require('supertest');
const { app }           = require('../server');

function sha256B64(buf) {
  return crypto.createHash('sha256').update(buf).digest('base64');
}

function hashK1Header(k1B64) {
  return sha256B64(Buffer.from(k1B64, 'base64'));
}

function makeFilePayload(fileBytes = Buffer.from('fake file contents')) {
  const key = crypto.randomBytes(32);
  const iv  = crypto.randomBytes(12);
  const k1  = crypto.randomBytes(32);
  const k2  = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) k2[i] = key[i] ^ k1[i];

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc    = Buffer.concat([cipher.update(fileBytes), cipher.final()]);
  const tag    = cipher.getAuthTag();

  return {
    payload: {
      ciphertext: Buffer.concat([enc, tag]).toString('base64'),
      iv:         iv.toString('base64'),
      k2:         k2.toString('base64'),
      k1Hash:     sha256B64(k1),
      isFile:     true,
      filename:   'notes.txt',
      mimetype:   'text/plain',
    },
    k1: k1.toString('base64'),
    fileBytes,
  };
}

// Mirrors clientDecrypt() in public/view.js for raw (non-text) bytes.
function clientDecryptRaw(ciphertextB64, ivB64, k1B64, k2B64) {
  const k1  = Buffer.from(k1B64, 'base64');
  const k2  = Buffer.from(k2B64, 'base64');
  const key = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) key[i] = k1[i] ^ k2[i];
  const ctWithTag = Buffer.from(ciphertextB64, 'base64');
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const ct  = ctWithTag.subarray(0, ctWithTag.length - 16);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

describe('File secrets', () => {
  test('creates and reveals a file secret with filename and mimetype intact', async () => {
    const { payload, k1, fileBytes } = makeFilePayload();
    const createRes = await request(app).post('/api/secret').send(payload);
    assert.equal(createRes.status, 201);

    const revealRes = await request(app)
      .get(`/api/secret/${createRes.body.id}`)
      .set('X-Key-Hash', hashK1Header(k1));
    assert.equal(revealRes.status, 200);
    assert.equal(revealRes.body.filename, 'notes.txt');
    assert.equal(revealRes.body.mimetype, 'text/plain');
    assert.equal(typeof revealRes.body.data, 'undefined'); // server never decrypts
    const decrypted = clientDecryptRaw(revealRes.body.ciphertext, revealRes.body.iv, k1, revealRes.body.k2);
    assert.equal(decrypted.toString(), fileBytes.toString());
  });

  test('rejects a file secret with a missing filename', async () => {
    const { payload } = makeFilePayload();
    delete payload.filename;
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });

  test('rejects a file secret with a missing mimetype', async () => {
    const { payload } = makeFilePayload();
    delete payload.mimetype;
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });

  test('rejects a filename over the max length', async () => {
    const { payload } = makeFilePayload();
    payload.filename = 'a'.repeat(256);
    const res = await request(app).post('/api/secret').send(payload);
    assert.equal(res.status, 400);
  });
});
