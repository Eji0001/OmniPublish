'use strict';

const { mockChain } = require('./helpers/db');

jest.mock('../config/database', () => ({
  supabase: { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

const { supabase } = require('../config/database');
const { upsertGoogleOAuthUser } = require('../routes/oauth');

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
      full_name: 'Google User',
    });
  });
});
