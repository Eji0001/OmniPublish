'use strict';

const request = require('supertest');
const { mockChain } = require('./helpers/db');

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
      aiRateLimiter: pass, mediaRateLimiter: pass, gdprExportRateLimiter: pass, gdprMutationRateLimiter: pass, gdprStatusRateLimiter: pass,
      resetPasswordRateLimiter: pass, publishRateLimiter: pass,
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
const { TEST_USER, generateAccessToken } = require('./helpers/auth');

function authHeader() {
  const { token } = generateAccessToken(TEST_USER);
  return { Authorization: `Bearer ${token}` };
}

beforeEach(() => jest.clearAllMocks());

describe('POST /api/v1/gdpr/export-data', () => {
  it('uses an explicit public-column select for users', async () => {
    const userQuery = {
      select: jest.fn(() => userQuery),
      eq: jest.fn(() => userQuery),
      single: jest.fn().mockResolvedValue({
        data: {
          id: TEST_USER.id,
          email: TEST_USER.email,
          full_name: 'Test User',
          avatar_url: 'https://example.com/avatar.png',
          role: 'user',
          plan: 'pro',
          is_verified: true,
          is_active: true,
          user_type: 'creator',
          onboarding_completed_at: null,
          last_login_at: null,
          marketing_consent: false,
          marketing_consent_at: null,
          timezone: 'UTC',
          created_at: '2026-01-01T00:00:00.000Z',
          updated_at: '2026-01-01T00:00:00.000Z',
        },
        error: null,
      }),
    };

    supabase.from.mockImplementation((table) => {
      if (table === 'users') return userQuery;
      return mockChain({ data: null, error: null }, { data: [], error: null, count: null });
    });

    const res = await request(app)
      .post('/api/v1/gdpr/export-data')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(userQuery.select).toHaveBeenCalledWith(
      'id, email, full_name, avatar_url, role, plan, is_verified, is_active, user_type, onboarding_completed_at, last_login_at, marketing_consent, marketing_consent_at, timezone, created_at, updated_at'
    );
    expect(userQuery.select.mock.calls[0][0]).not.toContain('password_hash');
    expect(userQuery.select.mock.calls[0][0]).not.toContain('failed_login_attempts');
    expect(userQuery.select.mock.calls[0][0]).not.toContain('locked_until');
    expect(res.body.data.user).not.toHaveProperty('password_hash');
    expect(res.body.data.user).not.toHaveProperty('failed_login_attempts');
    expect(res.body.data.user).not.toHaveProperty('locked_until');
    expect(res.body.data.user).not.toHaveProperty('deletion_requested_at');
  });
});
