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

jest.mock('../services/emailService', () => ({
  sendEmail: jest.fn().mockResolvedValue({ skipped: true }),
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
const { sendEmail } = require('../services/emailService');
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

    const candidateQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const claimQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const validQuery = mockChain({ data: null, error: null }, { data: validConnections, error: null });
    const expiredQuery = mockChain({ data: null, error: null }, { data: expiredConnections, error: null });
    const expiredUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });
    const publishedUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });

    supabase.from
      .mockReturnValueOnce(candidateQuery)
      .mockReturnValueOnce(claimQuery)
      .mockReturnValueOnce(validQuery)
      .mockReturnValueOnce(expiredQuery)
      .mockReturnValueOnce(expiredUpdateQuery)
      .mockReturnValueOnce(publishedUpdateQuery)
      .mockReturnValue(mockChain({ data: null, error: null }, { data: null, error: null }));

    publishToPlatform.mockResolvedValueOnce({ postId: 'x-123', url: 'https://x.com/i/web/status/x-123' });

    await processScheduledPosts();

    expect(validQuery.or).toHaveBeenCalledWith(expect.stringContaining('token_expires_at.gt.'));
    expect(publishToPlatform).toHaveBeenCalledTimes(1);
    expect(publishToPlatform).toHaveBeenCalledWith(expect.objectContaining({ platform: 'x' }));
    expect(expiredUpdateQuery.update).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed',
      error_message: expect.stringContaining('Platform token expired'),
    }));
    expect(sendEmail).not.toHaveBeenCalled();
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

    const candidateQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const claimQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const validQuery = mockChain({ data: null, error: null }, { data: [], error: null });
    const expiredQuery = mockChain({ data: null, error: null }, { data: [{ platform: 'linkedin', token_expires_at: new Date(Date.now() - 60 * 1000).toISOString() }], error: null });
    const expiredUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });
    const failedPostUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });

    supabase.from
      .mockReturnValueOnce(candidateQuery)
      .mockReturnValueOnce(claimQuery)
      .mockReturnValueOnce(validQuery)
      .mockReturnValueOnce(expiredQuery)
      .mockReturnValueOnce(expiredUpdateQuery)
      .mockReturnValueOnce(failedPostUpdateQuery)
      .mockReturnValue(mockChain({ data: null, error: null }, { data: null, error: null }));

    await processScheduledPosts();

    expect(publishToPlatform).not.toHaveBeenCalled();
    expect(expiredUpdateQuery.update).toHaveBeenCalledWith(expect.objectContaining({
      status: 'failed',
      error_message: expect.stringContaining('Platform token expired'),
    }));
    expect(failedPostUpdateQuery.update).toHaveBeenCalledWith(expect.objectContaining({ status: 'failed' }));
  });

  it('sends a completion notification when every platform publishes successfully', async () => {
    const duePost = {
      id: 'post-3',
      user_id: 'user-3',
      content: 'Weekly update',
      title: 'Weekly Wrap',
      post_platforms: [{ platform: 'x' }, { platform: 'linkedin' }],
      media_files: [],
    };

    const validConnections = [
      {
        platform: 'x',
        access_token_enc: 'enc-x',
        platform_user_id: 'x-user',
        token_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      },
      {
        platform: 'linkedin',
        access_token_enc: 'enc-li',
        platform_user_id: 'li-user',
        token_expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      },
    ];

    const candidateQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const claimQuery = mockChain({ data: null, error: null }, { data: [duePost], error: null });
    const validQuery = mockChain({ data: null, error: null }, { data: validConnections, error: null });
    const expiredQuery = mockChain({ data: null, error: null }, { data: [], error: null });
    const xUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });
    const linkedinUpdateQuery = mockChain({ data: null, error: null }, { data: null, error: null });
    const userQuery = mockChain({ data: { email: 'creator@example.com', full_name: 'Creator' }, error: null }, { data: null, error: null });

    supabase.from
      .mockReturnValueOnce(candidateQuery)
      .mockReturnValueOnce(claimQuery)
      .mockReturnValueOnce(validQuery)
      .mockReturnValueOnce(expiredQuery)
      .mockReturnValueOnce(xUpdateQuery)
      .mockReturnValueOnce(linkedinUpdateQuery)
      .mockReturnValueOnce(userQuery)
      .mockReturnValue(mockChain({ data: null, error: null }, { data: null, error: null }));

    publishToPlatform
      .mockResolvedValueOnce({ postId: 'x-123', url: 'https://x.com/i/web/status/x-123' })
      .mockResolvedValueOnce({ postId: 'li-123', url: 'https://www.linkedin.com/feed/update/li-123' });

    await processScheduledPosts();

    expect(sendEmail).toHaveBeenCalledTimes(1);
    expect(sendEmail).toHaveBeenCalledWith(expect.objectContaining({
      to: 'creator@example.com',
      subject: expect.stringContaining('Weekly Wrap'),
    }));
  });
});
