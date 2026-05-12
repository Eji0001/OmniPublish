'use strict';

const request = require('supertest');

jest.mock('../config/database', () => ({
  supabase: { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

jest.mock('../middleware/rateLimit', () => {
  const pass = (_req, _res, next) => next();
  return {
    globalRateLimiter: pass,
    authRateLimiter: pass,
    authSlowDown: pass,
    aiRateLimiter: pass,
    mediaRateLimiter: pass,
    gdprExportRateLimiter: pass,
    publishRateLimiter: pass,
  };
});

jest.mock('../middleware/csrf', () => ({
  verifyCSRF: (_req, _res, next) => next(),
  generateCSRFToken: () => 'test-csrf-token',
}));

const app = require('../server');

describe('Content Security Policy', () => {
  it('serves the root page with a nonce-based script policy', async () => {
    const res = await request(app).get('/');
    const csp = res.headers['content-security-policy'];
    const scriptSrc = csp.match(/script-src[^;]*/)?.[0] || '';

    expect(res.status).toBe(200);
    expect(scriptSrc).toMatch(/'nonce-[^']+'/);
    expect(scriptSrc).not.toContain("'unsafe-inline'");
    expect(res.text).toMatch(/<script nonce="[^"]+">/);
    expect(res.text).not.toContain('onclick="toggle(');
    expect(res.text).not.toContain('onclick="copyText(');
    expect(res.headers['expect-ct']).toBeUndefined();
  });
});
