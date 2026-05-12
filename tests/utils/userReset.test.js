'use strict';

const { mockChain } = require('../helpers/db');

jest.mock('../../config/database', () => ({
  supabase: { from: jest.fn(), auth: { admin: { listUsers: jest.fn(), deleteUser: jest.fn() } } },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

const { supabase } = require('../../config/database');
const { resetAllUsers, APP_TABLES } = require('../../utils/userReset');

beforeEach(() => jest.clearAllMocks());

describe('resetAllUsers', () => {
  it('revokes sessions, deletes app tables, and removes auth users', async () => {
    const sessionSelect = mockChain({ data: null, error: null }, { data: [{ jti: 'jti-1' }, { jti: 'jti-2' }], error: null });
    const revokeUpsert = mockChain({ data: null, error: null });
    const deleteChains = Object.fromEntries(
      APP_TABLES.map(table => [table, mockChain({ data: null, error: null }, { data: [{ id: `${table}-1` }], error: null })])
    );
    let userSessionsCalls = 0;

    supabase.from.mockImplementation((table) => {
      if (table === 'user_sessions') return userSessionsCalls++ === 0 ? sessionSelect : deleteChains.user_sessions;
      if (table === 'revoked_tokens') return revokeUpsert;
      return deleteChains[table] || mockChain({ data: null, error: null });
    });

    supabase.auth.admin.listUsers.mockResolvedValueOnce({
      data: { users: [{ id: 'auth-1' }, { id: 'auth-2' }] },
      error: null,
    });
    supabase.auth.admin.listUsers.mockResolvedValueOnce({
      data: { users: [] },
      error: null,
    });
    supabase.auth.admin.deleteUser.mockResolvedValue({ data: { user: null }, error: null });

    const summary = await resetAllUsers();

    expect(summary).toEqual({ revokedSessions: 2, authDeleted: 2, authSkipped: false });
    expect(revokeUpsert.upsert).toHaveBeenCalledWith([
      { jti: 'jti-1' },
      { jti: 'jti-2' },
    ], { onConflict: 'jti' });
    APP_TABLES.forEach(table => {
      expect(deleteChains[table].delete).toHaveBeenCalled();
    });
    expect(supabase.auth.admin.deleteUser).toHaveBeenNthCalledWith(1, 'auth-1');
    expect(supabase.auth.admin.deleteUser).toHaveBeenNthCalledWith(2, 'auth-2');
  });
});
