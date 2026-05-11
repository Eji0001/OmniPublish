'use strict';

jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => ({ from: jest.fn() })),
}));

jest.mock('../utils/logger', () => ({
  logger: {
    error: jest.fn(),
    warn: jest.fn(),
    info: jest.fn(),
    debug: jest.fn(),
  },
}));

const { executeWithRetry } = require('../config/database');

describe('executeWithRetry', () => {
  it('does not retry PGRST116', async () => {
    const err = Object.assign(new Error('No rows found'), { code: 'PGRST116' });
    const queryFn = jest.fn().mockRejectedValue(err);

    await expect(executeWithRetry(queryFn, 'db.query')).rejects.toThrow('No rows found');
    expect(queryFn).toHaveBeenCalledTimes(1);
  });
});
