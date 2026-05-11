'use strict';

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

const { idempotencyMiddleware } = require('../../middleware/idempotency');

describe('idempotencyMiddleware', () => {
  it('applies to auth reset-password requests', async () => {
    const req = {
      method: 'POST',
      path: '/v1/auth/reset-password',
      headers: {},
      user: { id: 'user-1' },
    };
    const res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    const next = jest.fn();

    await idempotencyMiddleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      code: 'IDEMPOTENCY_KEY_MISSING',
    }));
    expect(next).not.toHaveBeenCalled();
  });
});
