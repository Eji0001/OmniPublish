'use strict';

const request = require('supertest');
const { mockChain } = require('./helpers/db');
const { TEST_USER, generateAccessToken } = require('./helpers/auth');

jest.mock('../config/database', () => ({
  supabase: {
    from: jest.fn(),
    auth: { admin: { createUser: jest.fn().mockResolvedValue({ data: { user: null }, error: null }) } },
  },
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

jest.mock('../middleware/idempotency', () => ({
  idempotencyMiddleware: (_req, _res, next) => next(),
}));

const app = require('../server');
const { supabase } = require('../config/database');

function authHeader() {
  const { token } = generateAccessToken(TEST_USER);
  return { Authorization: `Bearer ${token}` };
}

function mockPlatformTables({ list = null, connection = null, singleConnection = null } = {}) {
  supabase.from.mockImplementation((table) => {
    if (table === 'revoked_tokens') {
      return mockChain({ data: null, error: null });
    }

    if (table === 'users') {
      return mockChain({ data: { id: TEST_USER.id, is_active: true }, error: null });
    }

    if (table === 'platform_connections') {
      if (list) {
        return mockChain({ data: connection, error: null }, { data: list, error: null });
      }

      return mockChain({ data: singleConnection || connection, error: null });
    }

    return mockChain({ data: null, error: null });
  });
}

beforeEach(() => jest.clearAllMocks());

describe('GET /api/v1/platforms', () => {
  it('returns all connections including inactive ones', async () => {
    mockPlatformTables({
      list: [
        { id: '1', platform: 'x', platform_username: '@x', is_active: true, connected_at: new Date().toISOString(), token_expires_at: null },
        { id: '2', platform: 'linkedin', platform_username: 'linked', is_active: false, connected_at: new Date().toISOString(), token_expires_at: null },
      ],
    });

    const res = await request(app)
      .get('/api/v1/platforms')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.platforms).toHaveLength(2);
    expect(res.body.platforms.find(p => p.platform === 'linkedin').is_active).toBe(false);
  });
});

describe('POST /api/v1/platforms/connect', () => {
  it('rejects invalid platform ids', async () => {
    mockPlatformTables();

    const res = await request(app)
      .post('/api/v1/platforms/connect')
      .set(authHeader())
      .send({ platform: "'); alert(1);//", accessToken: 'abc' });

    expect(res.status).toBe(422);
    expect(res.body.error).toBe('Validation failed');
  });

  it('accepts valid platform payloads', async () => {
    const upsertChain = mockChain({ data: { id: '1', platform: 'x', platform_username: '@x' }, error: null });
    const usersLookup = mockChain({ data: { id: TEST_USER.id, is_active: true }, error: null });

    supabase.from.mockImplementation((table) => {
      if (table === 'revoked_tokens') return mockChain({ data: null, error: null });
      if (table === 'users') return usersLookup;
      if (table === 'platform_connections') return upsertChain;
      return mockChain({ data: null, error: null });
    });

    const res = await request(app)
      .post('/api/v1/platforms/connect')
      .set(authHeader())
      .send({
        platform: 'x',
        accessToken: 'token-abc',
        platformUserId: 'user-1',
        platformUsername: 'Test User',
        expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      });

    expect(res.status).toBe(201);
    expect(upsertChain.upsert).toHaveBeenCalledWith(expect.objectContaining({
      user_id: TEST_USER.id,
      platform: 'x',
    }), expect.objectContaining({ onConflict: 'user_id,platform' }));
  });
});

describe('PATCH /api/v1/platforms/:id', () => {
  it('turns a connection on', async () => {
    const conn = {
      id: '1', platform: 'x', platform_username: '@x', is_active: false,
      connected_at: new Date().toISOString(), token_expires_at: null,
    };

    mockPlatformTables({ connection: conn, singleConnection: { ...conn, is_active: true } });

    const res = await request(app)
      .patch('/api/v1/platforms/1')
      .set(authHeader())
      .send({ is_active: true });

    expect(res.status).toBe(200);
    expect(res.body.connection.is_active).toBe(true);
  });

  it('turns a connection off', async () => {
    const conn = {
      id: '1', platform: 'x', platform_username: '@x', is_active: true,
      connected_at: new Date().toISOString(), token_expires_at: null,
    };

    mockPlatformTables({ connection: conn, singleConnection: { ...conn, is_active: false } });

    const res = await request(app)
      .patch('/api/v1/platforms/1')
      .set(authHeader())
      .send({ is_active: false });

    expect(res.status).toBe(200);
    expect(res.body.connection.is_active).toBe(false);
  });
});

describe('POST /api/v1/platforms/:id/verify', () => {
  it('returns verification status for an active connection', async () => {
    mockPlatformTables({
      connection: {
        id: '1', platform: 'x', platform_username: '@x', is_active: true,
        connected_at: new Date().toISOString(), token_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      },
    });

    const res = await request(app)
      .post('/api/v1/platforms/1/verify')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.connection.connection_status).toBe('active');
    expect(res.body.connection.token_valid).toBe(true);
  });
});
