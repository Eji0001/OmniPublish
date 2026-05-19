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
    gdprMutationRateLimiter: pass,
    gdprStatusRateLimiter: pass,
    resetPasswordRateLimiter: pass,
    publishRateLimiter: pass,
  };
});

jest.mock('../middleware/csrf', () => ({
  verifyCSRF: (_req, _res, next) => next(),
  generateCSRFToken: () => 'test-csrf-token',
}));

const app = require('../server');

describe('Logo downloads page', () => {
  it('serves the download page with direct asset links', async () => {
    const res = await request(app).get('/logo-downloads');

    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('OmniPublish Logo Downloads');
    expect(res.text).toContain('href="/favicon.ico" download="favicon.ico"');
    expect(res.text).toContain('href="/favicon.png" download="favicon.png"');
    expect(res.text).toContain('href="/favicon.svg" download="favicon.svg"');
  });
});
