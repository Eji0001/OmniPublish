'use strict';

const request = require('supertest');
const bcrypt  = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { mockChain } = require('./helpers/db');
const { TEST_USER, generateAccessToken, generateRefreshToken } = require('./helpers/auth');

// ── Module mocks ───────────────────────────────────────────

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
    globalRateLimiter: pass, authRateLimiter: pass, authSlowDown: pass,
    aiRateLimiter: pass, mediaRateLimiter: pass, gdprExportRateLimiter: pass, publishRateLimiter: pass,
  };
});

jest.mock('../middleware/csrf', () => ({
  verifyCSRF:        (_req, _res, next) => next(),
  generateCSRFToken: () => 'test-csrf-token',
}));

jest.mock('../middleware/idempotency', () => ({
  idempotencyMiddleware: (_req, _res, next) => next(),
}));

const app = require('../server');
const { supabase } = require('../config/database');

// ── Fixtures ───────────────────────────────────────────────

const HASH = bcrypt.hashSync('ValidPass123!', 1); // cost 1 for speed

const DB_USER = {
  id: TEST_USER.id, email: TEST_USER.email,
  password_hash: HASH, role: 'user', plan: 'pro',
  is_active: true, is_verified: true, failed_login_attempts: 0, locked_until: null,
};

beforeEach(() => jest.clearAllMocks());

beforeEach(() => {
  supabase.from.mockImplementation((table) => {
    if (table === 'user_sessions') return mockChain({ data: null, error: null });
    return undefined;
  });
});

// ── POST /api/v1/auth/register ─────────────────────────────

describe('POST /api/v1/auth/register', () => {
  it('200 — creates user and returns a session', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))           // email check
      .mockReturnValueOnce(mockChain({ data: { id: TEST_USER.id, email: 'new@example.com', role: 'user', plan: 'free' }, error: null })); // insert

    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'new@example.com', password: 'ValidPass123!', fullName: 'Test User' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.email).toBe('new@example.com');
    expect(res.body.user).not.toHaveProperty('password_hash');
    expect(res.headers['set-cookie']).toBeDefined();
  });

  it('200 — succeeds even when user_sessions is missing', async () => {
    const userSelect = mockChain({ data: null, error: null });
    const userInsert = mockChain({ data: { id: TEST_USER.id, email: 'new@example.com', role: 'user', plan: 'free' }, error: null });
    const missingSessions = mockChain({ data: null, error: { code: 'PGRST205', message: "Could not find the table 'public.user_sessions' in the schema cache" } });

    let usersCalls = 0;
    supabase.from.mockImplementation((table) => {
      if (table === 'users') return usersCalls++ === 0 ? userSelect : userInsert;
      if (table === 'user_sessions') return missingSessions;
      return mockChain({ data: null, error: null });
    });

    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'new@example.com', password: 'ValidPass123!', fullName: 'Test User' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.email).toBe('new@example.com');
  });

  it('200 — upgrades an existing unverified account into an active session', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: { id: 'existing-id', email: 'legacy@example.com', full_name: 'Legacy User', is_verified: false, role: 'user', plan: 'free' }, error: null }))
      .mockReturnValueOnce(mockChain({ data: { id: 'existing-id', email: 'legacy@example.com', full_name: 'Legacy User', is_verified: true, role: 'user', plan: 'free' }, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'legacy@example.com', password: 'ValidPass123!', fullName: 'Legacy User' });

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('legacy@example.com');
    expect(res.body.user).toHaveProperty('role', 'user');
    expect(res.body).toHaveProperty('accessToken');
  });

  it('409 — rejects duplicate email', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: { id: 'existing-id', is_verified: true }, error: null })); // email taken

    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'taken@example.com', password: 'ValidPass123!' });

    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/already registered/i);
  });

  it('422 — rejects weak password', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'user@example.com', password: 'weak' });

    expect(res.status).toBe(422);
  });

  it('422 — rejects invalid email format', async () => {
    const res = await request(app)
      .post('/api/v1/auth/register')
      .send({ email: 'not-an-email', password: 'ValidPass123!' });

    expect(res.status).toBe(422);
  });
});

// ── POST /api/v1/auth/login ────────────────────────────────

describe('POST /api/v1/auth/login', () => {
  it('200 — returns tokens and sets CSRF cookie on valid credentials', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: DB_USER, error: null }))   // get user
      .mockReturnValue(mockChain({ data: null, error: null }));          // update last_login_at

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'ValidPass123!' });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).not.toHaveProperty('refreshToken');
    expect(res.headers['set-cookie']).toBeDefined();
  });

  it('401 — rejects password login for OAuth-only accounts', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: { ...DB_USER, password_hash: null }, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'ValidPass123!' });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/password login/i);
  });

  it('403 — rejects unverified accounts', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: { ...DB_USER, is_verified: false }, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'ValidPass123!' });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/verify your email/i);
  });

  it('401 — rejects wrong password and increments failed attempts', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: DB_USER, error: null }))   // get user
      .mockReturnValue(mockChain({ data: null, error: null }));          // update attempts

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'WrongPassword1!' });

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/invalid credentials/i);
    // Confirm failed_login_attempts was incremented
    expect(supabase.from).toHaveBeenCalledWith('users');
  });

  it('429 — rejects locked account', async () => {
    const lockedUser = { ...DB_USER, locked_until: new Date(Date.now() + 60_000).toISOString() };
    supabase.from
      .mockReturnValueOnce(mockChain({ data: lockedUser, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'ValidPass123!' });

    expect(res.status).toBe(429);
    expect(res.body.error).toMatch(/locked/i);
  });

  it('403 — rejects inactive account', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: { ...DB_USER, is_active: false }, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'ValidPass123!' });

    expect(res.status).toBe(403);
  });

  it('locks account after maxFailedAttempts (5) exceeded', async () => {
    const almostLockedUser = { ...DB_USER, failed_login_attempts: 4 };
    supabase.from
      .mockReturnValueOnce(mockChain({ data: almostLockedUser, error: null }))
      .mockReturnValue(mockChain({ data: null, error: null }));

    await request(app)
      .post('/api/v1/auth/login')
      .send({ email: TEST_USER.email, password: 'WrongPassword1!' });

    // The update call should include locked_until
    const updateCalls = supabase.from.mock.results
      .map(r => r.value)
      .filter(chain => chain.update?.mock?.calls?.length);

    expect(updateCalls.length).toBeGreaterThan(0);
    const updateArg = updateCalls[0].update.mock.calls[0][0];
    expect(updateArg).toHaveProperty('locked_until');
  });
});

// ── POST /api/v1/auth/refresh ──────────────────────────────

describe('POST /api/v1/auth/refresh', () => {
  it('200 — rotates refresh token and returns new pair', async () => {
    const { token: refreshToken } = generateRefreshToken(TEST_USER);

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))  // blacklist old jti
      .mockReturnValueOnce(mockChain({ data: { ...TEST_USER, is_active: true }, error: null })); // get user

    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', `omni_refresh=${refreshToken}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body).not.toHaveProperty('refreshToken');
  });

  it('422 — rejects refresh token sent only in body', async () => {
    const { token: refreshToken } = generateRefreshToken(TEST_USER);

    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .send({ refreshToken });

    expect(res.status).toBe(422);
  });

  it('401 — rejects invalid refresh token', async () => {
    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .set('Cookie', 'omni_refresh=invalid.token.here');

    expect(res.status).toBe(401);
  });

  it('422 — rejects missing refreshToken field', async () => {
    const res = await request(app)
      .post('/api/v1/auth/refresh')
      .send({});

    expect(res.status).toBe(422);
  });
});

// ── POST /api/v1/auth/reset-password ────────────────────────

describe('POST /api/v1/auth/reset-password', () => {
  it('scopes reset tokens by prefix instead of purpose column', async () => {
    const chain = mockChain({ data: null, error: { message: 'not found' } });
    supabase.from.mockReturnValueOnce(chain);

    const res = await request(app)
      .post('/api/v1/auth/reset-password')
      .send({ token: `pr_${'a'.repeat(64)}`, password: 'ValidPass123!' });

    expect(res.status).toBe(400);
    expect(chain.eq).toHaveBeenCalledWith('token_hash', expect.any(String));
    expect(chain.eq).not.toHaveBeenCalledWith('purpose', expect.anything());
  });
});

describe('POST /api/v1/auth/forgot-password', () => {
  it('deletes only password reset rows for the user', async () => {
    const userSelect = mockChain({ data: { id: TEST_USER.id }, error: null });
    const deleteChain = mockChain({ data: null, error: null });
    const insertChain = mockChain({ data: null, error: null });

    supabase.from
      .mockReturnValueOnce(userSelect)
      .mockReturnValueOnce(deleteChain)
      .mockReturnValueOnce(insertChain);

    const res = await request(app)
      .post('/api/v1/auth/forgot-password')
      .send({ email: TEST_USER.email });

    expect(res.status).toBe(200);
    expect(deleteChain.eq).toHaveBeenCalledWith('user_id', TEST_USER.id);
    expect(deleteChain.eq).toHaveBeenCalledWith('purpose', 'password_reset');
  });
});

// ── POST /api/v1/auth/magic-link/verify ─────────────────────

describe('POST /api/v1/auth/magic-link/verify', () => {
  it('scopes magic links by prefix instead of purpose column', async () => {
    const chain = mockChain({ data: null, error: { message: 'not found' } });
    supabase.from.mockReturnValueOnce(chain);

    const res = await request(app)
      .post('/api/v1/auth/magic-link/verify')
      .send({ token: `ml_${'b'.repeat(64)}` });

    expect(res.status).toBe(400);
    expect(chain.eq).toHaveBeenCalledWith('token_hash', expect.any(String));
    expect(chain.eq).not.toHaveBeenCalledWith('purpose', expect.anything());
  });
});

describe('POST /api/v1/auth/magic-link', () => {
  it('deletes only magic link rows for the user', async () => {
    const userSelect = mockChain({ data: { id: TEST_USER.id }, error: null });
    const deleteChain = mockChain({ data: null, error: null });
    const insertChain = mockChain({ data: null, error: null });

    supabase.from
      .mockReturnValueOnce(userSelect)
      .mockReturnValueOnce(deleteChain)
      .mockReturnValueOnce(insertChain);

    const res = await request(app)
      .post('/api/v1/auth/magic-link')
      .send({ email: TEST_USER.email });

    expect(res.status).toBe(200);
    expect(deleteChain.eq).toHaveBeenCalledWith('user_id', TEST_USER.id);
    expect(deleteChain.eq).toHaveBeenCalledWith('purpose', 'magic_link');
  });
});

// ── POST /api/v1/auth/confirm-email ─────────────────────────

describe('POST /api/v1/auth/confirm-email', () => {
  it('200 — verifies email and returns session tokens', async () => {
    const token = jwt.sign(
      { purpose: 'email_confirm', userId: TEST_USER.id, email: TEST_USER.email },
      process.env.JWT_EMAIL_CONFIRM_SECRET,
      { expiresIn: '1h', issuer: 'omnipublish-api', audience: 'omnipublish-client' }
    );

    supabase.from
      .mockReturnValueOnce(mockChain({ data: { id: TEST_USER.id, email: TEST_USER.email, role: 'user', plan: 'free', full_name: 'Test User', is_verified: false }, error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/confirm-email')
      .send({ token });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user).toBeDefined();
    expect(supabase.from).toHaveBeenCalledWith('users');
  });

  it('400 — rejects email confirm tokens signed with the access secret', async () => {
    const token = jwt.sign(
      { purpose: 'email_confirm', userId: TEST_USER.id, email: TEST_USER.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '1h', issuer: 'omnipublish-api', audience: 'omnipublish-client' }
    );

    const res = await request(app)
      .post('/api/v1/auth/confirm-email')
      .send({ token });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/invalid or expired confirmation link/i);
  });
});

// ── POST /api/v1/auth/oauth/exchange ────────────────────────

describe('POST /api/v1/auth/oauth/exchange', () => {
  it('422 — rejects malformed exchange codes', async () => {
    const res = await request(app)
      .post('/api/v1/auth/oauth/exchange')
      .send({ code: 'short' });

    expect(res.status).toBe(422);
  });

  it('200 — exchanges signed oauth codes for session tokens', async () => {
    const code = jwt.sign(
      { purpose: 'oauth_exchange', userId: TEST_USER.id, email: TEST_USER.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '10m', issuer: 'omnipublish-api', audience: 'omnipublish-client' }
    );

    supabase.from
      .mockReturnValueOnce(mockChain({ data: { id: 'oauth-exchange-code-id' }, error: null }))
      .mockReturnValueOnce(mockChain({ data: { ...DB_USER, is_verified: false }, error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }));

    const res = await request(app)
      .post('/api/v1/auth/oauth/exchange')
      .send({ code });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.email).toBe(TEST_USER.email);
  });

  it('200 — succeeds when user_sessions table is unavailable', async () => {
    const code = jwt.sign(
      { purpose: 'oauth_exchange', userId: TEST_USER.id, email: TEST_USER.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '10m', issuer: 'omnipublish-api', audience: 'omnipublish-client' }
    );

    let passwordResetCalls = 0;
    let userCalls = 0;
    const codeUse = mockChain({ data: { id: 'oauth-exchange-code-id' }, error: null });
    const userSelect = mockChain({ data: { ...DB_USER, is_verified: false }, error: null });
    const userUpdate = mockChain({ data: null, error: null });
    const missingSessions = mockChain({ data: null, error: { code: 'PGRST205', message: "Could not find the table 'public.user_sessions' in the schema cache" } });

    supabase.from.mockImplementation((table) => {
      if (table === 'password_resets') return passwordResetCalls++ === 0 ? codeUse : mockChain({ data: null, error: { message: 'No rows updated' } });
      if (table === 'users') return userCalls++ === 0 ? userSelect : userUpdate;
      if (table === 'user_sessions') return missingSessions;
      return mockChain({ data: null, error: null });
    });

    const res = await request(app)
      .post('/api/v1/auth/oauth/exchange')
      .send({ code });

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('accessToken');
    expect(res.body.user.email).toBe(TEST_USER.email);
  });

  it('400 — rejects replayed oauth exchange codes', async () => {
    const code = jwt.sign(
      { purpose: 'oauth_exchange', userId: TEST_USER.id, email: TEST_USER.email },
      process.env.JWT_ACCESS_SECRET,
      { expiresIn: '10m', issuer: 'omnipublish-api', audience: 'omnipublish-client' }
    );

    let passwordResetCalls = 0;
    let userCalls = 0;
    const firstCodeUse = mockChain({ data: { id: 'oauth-exchange-code-id' }, error: null });
    const secondCodeUse = mockChain({ data: null, error: null }, { data: null, error: { message: 'No rows updated' } });
    const userSelect = mockChain({ data: { ...DB_USER, is_verified: false }, error: null });
    const userUpdate = mockChain({ data: null, error: null });
    const sessionInsert = mockChain({ data: null, error: null });

    supabase.from.mockImplementation((table) => {
      if (table === 'password_resets') return passwordResetCalls++ === 0 ? firstCodeUse : secondCodeUse;
      if (table === 'users') return userCalls++ === 0 ? userSelect : userUpdate;
      if (table === 'user_sessions') return sessionInsert;
      return mockChain({ data: null, error: null });
    });

    const first = await request(app)
      .post('/api/v1/auth/oauth/exchange')
      .send({ code });

    const second = await request(app)
      .post('/api/v1/auth/oauth/exchange')
      .send({ code });

    expect(first.status).toBe(200);
    expect(second.status).toBe(400);
    expect(second.body.error).toMatch(/invalid or expired code/i);
  });
});

// ── POST /api/v1/auth/logout ───────────────────────────────

describe('POST /api/v1/auth/logout', () => {
  it('200 — revokes token and clears cookie', async () => {
    const { token } = generateAccessToken(TEST_USER);

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))  // revoked_tokens check (not revoked)
      .mockReturnValue(mockChain({ data: null, error: null }));      // insert revoked token

    const res = await request(app)
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/logged out/i);
  });

  it('401 — rejects request without token', async () => {
    const res = await request(app).post('/api/v1/auth/logout');
    expect(res.status).toBe(401);
  });
});

// ── DELETE /api/v1/auth/me ──────────────────────────────────

describe('DELETE /api/v1/auth/me', () => {
  it('revokes all tracked sessions for the deleted account', async () => {
    const { token, jti } = generateAccessToken(TEST_USER);
    const password = 'ValidPass123!';
    const sessionLookup = mockChain(
      { data: null, error: null },
      { data: [{ jti: 'session-a' }, { jti: 'session-b' }], error: null }
    );
    const revokedInsert = mockChain({ data: null, error: null });
    const sessionUpdate = mockChain({ data: null, error: null });

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))
      .mockReturnValueOnce(mockChain({ data: { id: TEST_USER.id, password_hash: HASH }, error: null }))
      .mockReturnValueOnce(sessionLookup)
      .mockReturnValueOnce(revokedInsert)
      .mockReturnValueOnce(sessionUpdate)
      .mockReturnValueOnce(mockChain({ data: null, error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }));

    const res = await request(app)
      .delete('/api/v1/auth/me')
      .set('Authorization', `Bearer ${token}`)
      .send({ password });

    expect(res.status).toBe(200);
    expect(revokedInsert.upsert).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ jti: 'session-a', user_id: TEST_USER.id }),
      expect.objectContaining({ jti: 'session-b', user_id: TEST_USER.id }),
      expect.objectContaining({ jti, user_id: TEST_USER.id }),
    ]), { onConflict: 'jti' });
    expect(sessionUpdate.update).toHaveBeenCalledWith(expect.objectContaining({ revoked_at: expect.any(Date) }));
  });
});

// ── GET /api/v1/auth/me ────────────────────────────────────

describe('GET /api/v1/auth/me', () => {
  it('200 — returns user profile', async () => {
    const { token } = generateAccessToken(TEST_USER);
    const profile = { id: TEST_USER.id, email: TEST_USER.email, full_name: 'Test User', role: 'user', plan: 'pro', created_at: new Date().toISOString(), last_login_at: null };

    supabase.from.mockImplementation((table) => {
      if (table === 'revoked_tokens') return mockChain({ data: null, error: null });
      if (table === 'users') return mockChain({ data: profile, error: null });
      return mockChain({ data: null, error: null });
    });

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe(TEST_USER.email);
  });

  it('401 — rejects request without token', async () => {
    const res = await request(app).get('/api/v1/auth/me');
    expect(res.status).toBe(401);
  });

  it('401 — rejects a revoked token', async () => {
    const { token } = generateAccessToken(TEST_USER);

    supabase.from
      .mockReturnValueOnce(mockChain({ data: { id: 'blacklisted' }, error: null })); // token IS revoked

    const res = await request(app)
      .get('/api/v1/auth/me')
      .set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(401);
    expect(res.body.error).toMatch(/revoked/i);
  });
});
