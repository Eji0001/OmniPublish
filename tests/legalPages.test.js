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

describe('Legal pages', () => {
  it('serves terms page', async () => {
    const res = await request(app).get('/terms');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('Terms of Service');
    expect(res.text).toContain('OmniPublish');
  });

  it('serves privacy page', async () => {
    const res = await request(app).get('/privacy');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('Privacy Policy');
    expect(res.text).toContain('OmniPublish');
  });

  it('links legal pages from the homepage footer', async () => {
    const res = await request(app).get('/');
    expect(res.status).toBe(200);
    expect(res.text).toContain('href="/terms"');
    expect(res.text).toContain('href="/privacy"');
  });
});
