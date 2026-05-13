'use strict';

const { mockChain } = require('../helpers/db');
const { TEST_USER, generateAccessToken } = require('../helpers/auth');

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
const { recordSession, revokeUserSessions, verifyToken } = require('../../middleware/auth');

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

  it('rejects access for deleted accounts', async () => {
    const { token } = generateAccessToken(TEST_USER);
    const revokedLookup = mockChain({ data: null, error: null });
    const deletedUserLookup = mockChain({ data: null, error: null });
    const res = { status: jest.fn(() => res), json: jest.fn() };
    const next = jest.fn();

    supabase.from
      .mockReturnValueOnce(revokedLookup)
      .mockReturnValueOnce(deletedUserLookup);

    await verifyToken({ headers: { authorization: `Bearer ${token}` }, ip: '127.0.0.1' }, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ error: 'Account not found or inactive' });
    expect(next).not.toHaveBeenCalled();
  });

  it('allows access for active accounts', async () => {
    const { token } = generateAccessToken(TEST_USER);
    const revokedLookup = mockChain({ data: null, error: null });
    const activeUserLookup = mockChain({ data: { id: TEST_USER.id, is_active: true }, error: null });
    const res = { status: jest.fn(() => res), json: jest.fn() };
    const next = jest.fn();

    supabase.from
      .mockReturnValueOnce(revokedLookup)
      .mockReturnValueOnce(activeUserLookup);

    await verifyToken({ headers: { authorization: `Bearer ${token}` }, ip: '127.0.0.1' }, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
    expect(activeUserLookup.eq).toHaveBeenCalledWith('id', TEST_USER.id);
  });
});
