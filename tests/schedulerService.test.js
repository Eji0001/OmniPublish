'use strict';

const { mockChain } = require('./helpers/db');

jest.mock('../config/database', () => ({
  supabase: { from: jest.fn() },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

jest.mock('../services/platformService', () => ({
  publishToPlatform: jest.fn(),
}));

jest.mock('../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { supabase } = require('../config/database');
const { publishToPlatform } = require('../services/platformService');
const { processScheduledPosts } = require('../services/schedulerService');

beforeEach(() => jest.clearAllMocks());

describe('processScheduledPosts', () => {
  it('skips expired platform tokens and flags them for reconnect', async () => {
    const duePost = {
      id: 'post-1',
      user_id: 'user-1',
      content: 'Hello world',
      title: 'Scheduled post',
      post_platforms: [{ platform: 'x' }, { platform: 'linkedin' }],
      media_files: [],
    };

    const validConnections = [{
      platform: 'x',
      access_token_enc: 'enc-x',
      platform_user_id: 'x-user',
      token_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
    }];
    const expiredConnections = [{
      platform: 'linkedin',
      token_expires_at: new Date(Date.now() - 60 * 1000).toISOString(),
    }];

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [duePost], error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: validConnections, error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: expiredConnections, error: null }))
      .mockReturnValue(mockChain({ data: null, error: null }, { data: null, error: null }));

    publishToPlatform.mockResolvedValueOnce({ postId: 'x-123', url: 'https://x.com/i/web/status/x-123' });

    await processScheduledPosts();

    expect(supabase.from.mock.results[1].value.or).toHaveBeenCalledWith(expect.stringContaining('token_expires_at.gt.'));
    expect(publishToPlatform).toHaveBeenCalledTimes(1);
    expect(publishToPlatform).toHaveBeenCalledWith(expect.objectContaining({ platform: 'x' }));
    expect(supabase.from.mock.results[3].value.update).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed',
      error_message: expect.stringContaining('Platform token expired'),
    }));
  });

  it('fails the post when all target tokens are expired', async () => {
    const duePost = {
      id: 'post-2',
      user_id: 'user-2',
      content: 'Hello again',
      title: 'Expired only',
      post_platforms: [{ platform: 'linkedin' }],
      media_files: [],
    };

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [duePost], error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [], error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [{ platform: 'linkedin', token_expires_at: new Date(Date.now() - 60 * 1000).toISOString() }], error: null }))
      .mockReturnValue(mockChain({ data: null, error: null }, { data: null, error: null }));

    await processScheduledPosts();

    expect(publishToPlatform).not.toHaveBeenCalled();
    expect(supabase.from.mock.results[3].value.update).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed',
      error_message: expect.stringContaining('Platform token expired'),
    }));
    expect(supabase.from.mock.results[4].value.update).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }));
  });
});
