'use strict';

const express = require('express');
const request = require('supertest');

jest.mock('../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { gdprExportRateLimiter } = require('../middleware/rateLimit');

function createApp(userId) {
  const app = express();
  app.use((req, _res, next) => {
    req.user = { id: userId };
    next();
  });
  app.post('/api/v1/gdpr/export-data', gdprExportRateLimiter, (_req, res) => {
    res.json({ ok: true });
  });
  return app;
}

describe('gdprExportRateLimiter', () => {
  it('allows two exports per user per hour and blocks the third', async () => {
    const app = createApp('user-1');

    await expect(request(app).post('/api/v1/gdpr/export-data')).resolves.toMatchObject({ status: 200 });
    await expect(request(app).post('/api/v1/gdpr/export-data')).resolves.toMatchObject({ status: 200 });

    const third = await request(app).post('/api/v1/gdpr/export-data');
    expect(third.status).toBe(429);
    expect(third.body.error).toMatch(/too many requests/i);
  });

  it('tracks each user independently', async () => {
    const app1 = createApp('user-2');
    const app2 = createApp('user-3');

    await request(app1).post('/api/v1/gdpr/export-data');
    await request(app1).post('/api/v1/gdpr/export-data');

    const otherUser = await request(app2).post('/api/v1/gdpr/export-data');
    expect(otherUser.status).toBe(200);
  });
});
