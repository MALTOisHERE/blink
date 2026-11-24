'use strict';

// ── Polar license activate/validate/deactivate (mocked) ─────────────────────
// license.test.js only ever exercises the BLINK_PRO_DEV_KEY shortcut, which
// never calls Polar at all. This covers the real API call path instead -
// activate, server-side validate, deactivate - the same way
// oauth-success.test.js stubs global.fetch for Google/GitHub, since Polar's
// API base is hardcoded (no env var to redirect it to a local server).
const realFetch = global.fetch;

function jsonResponse(body, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}

process.env.NODE_ENV              = 'test';
process.env.SECRET_KEY            = 'test-hmac-secret-key-for-k3';
process.env.CIPHER_KEY            = 'deadbeef'.repeat(8);
process.env.SESSION_SECRET        = 'test-session-secret';
process.env.BLINK_PRO_DEV_KEY     = 'test-dev-pro-key-222';
process.env.POLAR_ORGANIZATION_ID = 'org-test-id';
process.env.POLAR_ACCESS_TOKEN    = 'polar-access-token-test';
process.env.POLAR_BENEFIT_ID      = 'benefit-test-id';
process.env.LICENSES_FILE = require('node:path').join(__dirname, '.tmp-licenses-polar.json');

const { describe, test, after } = require('node:test');
const assert                    = require('node:assert/strict');
const fs                        = require('node:fs');
const request                   = require('supertest');
const { app }                  = require('../server');

after(() => {
  global.fetch = realFetch;
  try { fs.unlinkSync(process.env.LICENSES_FILE); } catch {}
});

describe('Polar license activation (real API path, mocked)', () => {
  test('a valid key activates, validates as Pro, and deactivates cleanly', async () => {
    const activationId = '11111111-1111-4111-8111-111111111111';
    global.fetch = async (url, options) => {
      const u = String(url);
      if (u.endsWith('/v1/customer-portal/license-keys/activate')) {
        return jsonResponse({ id: activationId, license_key_id: 'lk-1', label: 'account-x', meta: {} });
      }
      if (u.endsWith('/v1/license-keys/validate')) {
        assert.equal(options.headers.Authorization, 'Bearer polar-access-token-test');
        return jsonResponse({ status: 'granted', benefit_id: 'benefit-test-id' });
      }
      if (u.endsWith('/v1/customer-portal/license-keys/deactivate')) {
        return jsonResponse({}, 204);
      }
      throw new Error(`unexpected fetch to ${u}`);
    };

    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const activateRes = await agent.post('/api/license/activate').send({ licenseKey: 'a-valid-polar-key' });
    assert.equal(activateRes.body.valid, true);

    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.isPro, true);

    const deactivateRes = await agent.post('/api/license/deactivate');
    assert.equal(deactivateRes.body.ok, true);

    const meAfter = await agent.get('/api/auth/me');
    assert.equal(meAfter.body.isPro, false);
  });

  test('a key already at its activation limit is rejected', async () => {
    global.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith('/v1/customer-portal/license-keys/activate')) {
        return jsonResponse({ detail: 'License key has reached its activation limit' }, 403);
      }
      throw new Error(`unexpected fetch to ${u}`);
    };
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    const res = await agent.post('/api/license/activate').send({ licenseKey: 'an-exhausted-key' });
    assert.equal(res.body.valid, false);
    assert.equal(res.body.error, 'activation_limit');
  });

  test('a key for an unrelated Polar benefit is rejected at validation time', async () => {
    const activationId = '22222222-2222-4222-8222-222222222222';
    global.fetch = async (url) => {
      const u = String(url);
      if (u.endsWith('/v1/customer-portal/license-keys/activate')) {
        return jsonResponse({ id: activationId });
      }
      if (u.endsWith('/v1/license-keys/validate')) {
        return jsonResponse({ status: 'granted', benefit_id: 'some-other-benefit' });
      }
      throw new Error(`unexpected fetch to ${u}`);
    };
    const agent = request.agent(app);
    await agent.get('/api/auth/dev-login');
    await agent.post('/api/license/activate').send({ licenseKey: 'a-wrong-benefit-key' });
    const me = await agent.get('/api/auth/me');
    assert.equal(me.body.isPro, false);
  });
});
