'use strict';

const request = require('supertest');
const { mockChain } = require('./helpers/db');
const { TEST_USER, generateAccessToken } = require('./helpers/auth');
const { generateOAuthState } = require('../middleware/oauthStateVerification');

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
      gdprExportRateLimiter: pass, gdprMutationRateLimiter: pass, gdprStatusRateLimiter: pass,
      resetPasswordRateLimiter: pass,
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
beforeEach(() => {
  global.fetch = jest.fn();
});

describe('YouTube OAuth flow', () => {
  it('returns a Google auth URL with consent and PKCE', async () => {
    mockPlatformTables();

    const res = await request(app)
      .get('/api/v1/platforms/youtube/auth?returnTo=' + encodeURIComponent('http://localhost:3000/#dashboard'))
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.url).toContain('https://accounts.google.com/o/oauth2/v2/auth');
    expect(res.body.url).toContain('access_type=offline');
    expect(res.body.url).toContain('prompt=consent');
    expect(res.body.url).toContain('code_challenge=');
    expect(res.headers['set-cookie']?.join(';')).toContain('oauth_pkce_youtube=');
  });

  it('requests permanent refresh access for Reddit OAuth', async () => {
    mockPlatformTables();

    const res = await request(app)
      .get('/api/v1/platforms/reddit/auth?returnTo=' + encodeURIComponent('http://localhost:3000/#dashboard'))
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.url).toContain('duration=permanent');
    expect(res.body.url).toContain('https://www.reddit.com/api/v1/authorize');
  });

  it('stores the YouTube OAuth connection on callback', async () => {
    const upsertChain = mockChain({ data: null, error: null }, { data: null, error: null });
    const state = (await generateOAuthState('youtube', TEST_USER.id, 'http://localhost:3000/#dashboard')).state;

    supabase.from.mockImplementation((table) => {
      if (table === 'revoked_tokens') return mockChain({ data: null, error: null });
      if (table === 'users') return mockChain({ data: { id: TEST_USER.id, is_active: true }, error: null });
      if (table === 'platform_connections') return upsertChain;
      return mockChain({ data: null, error: null });
    });

    global.fetch
      .mockResolvedValueOnce({ json: async () => ({ access_token: 'yt-access', refresh_token: 'yt-refresh', expires_in: 3600 }) })
      .mockResolvedValueOnce({ json: async () => ({ items: [{ id: 'channel-1', snippet: { title: 'YT Channel' } }] }) });

    const res = await request(app)
      .get('/api/v1/platforms/youtube/callback?code=code-123&state=' + encodeURIComponent(state));

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('platform_success=youtube');
    expect(res.headers.location).toContain('#dashboard');
    expect(upsertChain.upsert).toHaveBeenCalledWith(expect.objectContaining({
      user_id: TEST_USER.id,
      platform: 'youtube',
      platform_user_id: 'channel-1',
      platform_username: 'YT Channel',
      refresh_token_enc: expect.any(String),
    }), expect.objectContaining({ onConflict: 'user_id,platform' }));
  });
});

describe('Snapchat OAuth flow', () => {
  it('returns a Snapchat auth URL with PKCE and Snap scopes', async () => {
    mockPlatformTables();

    const res = await request(app)
      .get('/api/v1/platforms/snapchat/auth?returnTo=' + encodeURIComponent('http://localhost:3000/#dashboard'))
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.url).toContain('https://accounts.snapchat.com/accounts/oauth2/auth');
    expect(res.body.url).toContain('code_challenge=');
    expect(res.body.url).toContain(encodeURIComponent('https://auth.snapchat.com/oauth2/api/user.display_name'));
    expect(res.headers['set-cookie']?.join(';')).toContain('oauth_pkce_snapchat=');
  });

  it('stores the Snapchat OAuth connection on callback without a profile lookup', async () => {
    const upsertChain = mockChain({ data: null, error: null }, { data: null, error: null });
    const state = (await generateOAuthState('snapchat', TEST_USER.id, 'http://localhost:3000/#dashboard')).state;

    supabase.from.mockImplementation((table) => {
      if (table === 'revoked_tokens') return mockChain({ data: null, error: null });
      if (table === 'users') return mockChain({ data: { id: TEST_USER.id, is_active: true }, error: null });
      if (table === 'platform_connections') return upsertChain;
      return mockChain({ data: null, error: null });
    });

    global.fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        access_token: 'snap-access',
        refresh_token: 'snap-refresh',
        expires_in: 3600,
        scope: 'https://auth.snapchat.com/oauth2/api/user.display_name https://auth.snapchat.com/oauth2/api/user.external_id',
      }),
    });

    const res = await request(app)
      .get('/api/v1/platforms/snapchat/callback?code=code-123&state=' + encodeURIComponent(state));

    expect(res.status).toBe(302);
    expect(res.headers.location).toContain('platform_success=snapchat');
    expect(res.headers.location).toContain('#dashboard');
    expect(upsertChain.upsert).toHaveBeenCalledWith(expect.objectContaining({
      user_id: TEST_USER.id,
      platform: 'snapchat',
      platform_user_id: null,
      platform_username: 'Snapchat User',
      refresh_token_enc: expect.any(String),
      scopes: expect.arrayContaining([
        'https://auth.snapchat.com/oauth2/api/user.display_name',
        'https://auth.snapchat.com/oauth2/api/user.external_id',
      ]),
    }), expect.objectContaining({ onConflict: 'user_id,platform' }));
  });
});

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
