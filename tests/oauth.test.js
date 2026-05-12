'use strict';

const { mockChain } = require('./helpers/db');
const { generateOAuthState, verifyOAuthState } = require('../middleware/oauthStateVerification');

jest.setTimeout(15000);

jest.mock('../config/database', () => ({
  supabase: { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

const { supabase } = require('../config/database');
const { upsertGoogleOAuthUser, issueOAuthExchangeCode } = require('../routes/oauth');

beforeEach(() => jest.clearAllMocks());

describe('upsertGoogleOAuthUser', () => {
  it('creates Google users as verified immediately', async () => {
    const createdUser = {
      id: 'new-google-user',
      email: 'google@example.com',
      role: 'user',
      plan: 'free',
      full_name: 'Google User',
      is_verified: true,
    };

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))
      .mockReturnValueOnce(mockChain({ data: createdUser, error: null }));

    const user = await upsertGoogleOAuthUser('google@example.com', 'Google User');

    expect(user).toEqual(createdUser);
    expect(supabase.from).toHaveBeenCalledWith('users');
    expect(supabase.from.mock.results[1].value.insert.mock.calls[0][0]).toMatchObject({
      email: 'google@example.com',
      is_active: true,
      is_verified: true,
      full_name: 'Google User',
    });
  });

  it('normalizes Google email casing before lookup and insert', async () => {
    const createdUser = {
      id: 'case-google-user',
      email: 'google@example.com',
      role: 'user',
      plan: 'free',
      full_name: 'Google User',
      is_verified: true,
    };

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))
      .mockReturnValueOnce(mockChain({ data: createdUser, error: null }));

    const user = await upsertGoogleOAuthUser('Google@Example.COM', 'Google User');

    expect(user).toEqual(createdUser);
    expect(supabase.from.mock.results[0].value.ilike).toHaveBeenCalledWith('email', 'google@example.com');
    expect(supabase.from.mock.results[0].value.order).toHaveBeenCalledWith('locked_until', { ascending: true, nullsFirst: true });
    expect(supabase.from.mock.results[0].value.order).toHaveBeenCalledWith('failed_login_attempts', { ascending: true });
    expect(supabase.from.mock.results[1].value.insert.mock.calls[0][0].email).toBe('google@example.com');
  });

  it('updates existing Google users to verified on sign-in', async () => {
    const existingUser = {
      id: 'existing-google-user',
      email: 'google@example.com',
      role: 'user',
      plan: 'free',
      full_name: null,
      is_verified: false,
    };
    const updatedUser = {
      ...existingUser,
      full_name: 'Google User',
      is_verified: true,
    };

    supabase.from
      .mockReturnValueOnce(mockChain({ data: existingUser, error: null }))
      .mockReturnValueOnce(mockChain({ data: updatedUser, error: null }));

    const user = await upsertGoogleOAuthUser('google@example.com', 'Google User');

    expect(user).toEqual(updatedUser);
    expect(supabase.from.mock.results[1].value.update.mock.calls[0][0]).toMatchObject({
      is_verified: true,
      is_active: true,
      failed_login_attempts: 0,
      locked_until: null,
      full_name: 'Google User',
    });
  });
});

describe('OAuth state return target', () => {
  it('round-trips the frontend return origin', async () => {
    const { state } = await generateOAuthState('google', null, 'http://localhost:3000');
    const payload = await verifyOAuthState(state, 'google');

    expect(payload.returnTo).toBe('http://localhost:3000');
  });
});

describe('issueOAuthExchangeCode', () => {
  it('stores the exchange code hash for one-time use', async () => {
    const user = { id: 'oauth-user', email: 'oauth@example.com' };

    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null }));

    const code = await issueOAuthExchangeCode(user);

    expect(code).toEqual(expect.any(String));
    expect(supabase.from).toHaveBeenCalledWith('password_resets');
    expect(supabase.from.mock.results[0].value.insert.mock.calls[0][0]).toMatchObject({
      user_id: user.id,
      purpose: 'oauth_exchange',
    });
  });
});
