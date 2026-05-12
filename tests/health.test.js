'use strict';

const request = require('supertest');

jest.mock('../config/database', () => ({
  supabase:       { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck:  jest.fn().mockResolvedValue(true),
  execute:        jest.fn(),
  executeWithRetry: jest.fn(),
}));

jest.mock('../middleware/rateLimit', () => {
  const pass = (_req, _res, next) => next();
  return {
    globalRateLimiter:  pass,
    authRateLimiter:    pass,
    authSlowDown:       pass,
    aiRateLimiter:      pass,
    mediaRateLimiter:   pass,
    gdprExportRateLimiter: pass,
    publishRateLimiter: pass,
  };
});

const app = require('../server');

describe('GET /api/v1/health/live', () => {
  it('returns 200 with status ok', async () => {
    const res = await request(app).get('/api/v1/health/live');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });
});

describe('GET /api/v1/health/ready', () => {
  it('returns 200 when DB is healthy', async () => {
    const { dbHealthCheck } = require('../config/database');
    dbHealthCheck.mockResolvedValueOnce(true);

    const res = await request(app).get('/api/v1/health/ready');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ready');
    expect(res.body.db).toBe('ok');
  });

  it('returns 503 when DB is unreachable', async () => {
    const { dbHealthCheck } = require('../config/database');
    dbHealthCheck.mockResolvedValueOnce(false);

    const res = await request(app).get('/api/v1/health/ready');
    expect(res.status).toBe(503);
    expect(res.body.status).toBe('not_ready');
  });
});
