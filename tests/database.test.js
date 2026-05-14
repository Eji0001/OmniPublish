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
const { supabase, dbSchemaHealthCheck, REQUIRED_RELATIONS } = require('../config/database');

describe('executeWithRetry', () => {
  it('does not retry PGRST116', async () => {
    const err = Object.assign(new Error('No rows found'), { code: 'PGRST116' });
    const queryFn = jest.fn().mockRejectedValue(err);

    await expect(executeWithRetry(queryFn, 'db.query')).rejects.toThrow('No rows found');
    expect(queryFn).toHaveBeenCalledTimes(1);
  });
});

describe('dbSchemaHealthCheck', () => {
  beforeEach(() => {
    supabase.from.mockReset();
  });

  it('reports success when all MVP relations are present', async () => {
    supabase.from.mockImplementation(() => ({
      select: jest.fn(() => ({
        limit: jest.fn().mockResolvedValue({ data: [], error: null }),
      })),
    }));

    const result = await dbSchemaHealthCheck();

    expect(result.ok).toBe(true);
    expect(result.missingRelations).toEqual([]);
    expect(supabase.from).toHaveBeenCalledTimes(REQUIRED_RELATIONS.length);
  });

  it('reports missing relations when a required table is absent', async () => {
    supabase.from.mockImplementation((relation) => ({
      select: jest.fn(() => ({
        limit: jest.fn().mockResolvedValue(
          relation === 'platform_connections'
            ? { data: null, error: { message: 'relation does not exist', code: '42P01' } }
            : { data: [], error: null }
        ),
      })),
    }));

    const result = await dbSchemaHealthCheck();

    expect(result.ok).toBe(false);
    expect(result.missingRelations).toContain('platform_connections');
  });

  it('keeps readiness green when only support tables are missing', async () => {
    supabase.from.mockImplementation((relation) => ({
      select: jest.fn(() => ({
        limit: jest.fn().mockResolvedValue(
          relation === 'retry_queue'
            ? { data: null, error: { message: 'relation does not exist', code: '42P01' } }
            : { data: [], error: null }
        ),
      })),
    }));

    const result = await dbSchemaHealthCheck();

    expect(result.ok).toBe(true);
    expect(result.missingSupportRelations).toContain('retry_queue');
    expect(result.missingCoreRelations).toEqual([]);
  });
});
