'use strict';

const { mockChain } = require('../helpers/db');

jest.mock('../../config/database', () => ({
  supabase: { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

jest.mock('../../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { supabase } = require('../../config/database');
const { recordSession, revokeUserSessions } = require('../../middleware/auth');

beforeEach(() => jest.clearAllMocks());

describe('session tracking helpers', () => {
  it('records issued sessions', async () => {
    const chain = mockChain({ data: null, error: null });
    supabase.from.mockReturnValueOnce(chain);

    await recordSession('user-1', 'jti-1');

    expect(chain.upsert).toHaveBeenCalledWith(expect.objectContaining({
      user_id: 'user-1',
      jti: 'jti-1',
    }), { onConflict: 'jti' });
  });

  it('revokes every tracked session for a user', async () => {
    const sessionLookup = mockChain({ data: null, error: null }, { data: [{ jti: 'jti-a' }, { jti: 'jti-b' }], error: null });
    const revokedInsert = mockChain({ data: null, error: null });
    const sessionUpdate = mockChain({ data: null, error: null });

    supabase.from
      .mockReturnValueOnce(sessionLookup)
      .mockReturnValueOnce(revokedInsert)
      .mockReturnValueOnce(sessionUpdate);

    await revokeUserSessions('user-1', 'current-jti');

    expect(revokedInsert.upsert).toHaveBeenCalledWith(expect.arrayContaining([
      expect.objectContaining({ jti: 'jti-a', user_id: 'user-1' }),
      expect.objectContaining({ jti: 'jti-b', user_id: 'user-1' }),
      expect.objectContaining({ jti: 'current-jti', user_id: 'user-1' }),
    ]), { onConflict: 'jti' });
    expect(sessionUpdate.update).toHaveBeenCalledWith(expect.objectContaining({ revoked_at: expect.any(Date) }));
  });
});
