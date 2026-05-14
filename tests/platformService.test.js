'use strict';

const mockDecrypt = jest.fn(() => 'access-token');
const mockEncrypt = jest.fn((value) => `enc:${value}`);
const mockPlatformBreakerExecute = jest.fn(async (fn) => fn());

jest.mock('../middleware/circuitBreaker', () => ({
  anthropicBreaker: { execute: jest.fn(async (fn) => fn()) },
  platformApisBreaker: { execute: mockPlatformBreakerExecute },
}));

jest.mock('../utils/encryption', () => ({
  decrypt: mockDecrypt,
  encrypt: mockEncrypt,
}));

jest.mock('../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { publishToPlatform } = require('../services/platformService');

beforeEach(() => {
  jest.clearAllMocks();
  global.fetch = jest.fn();
});

describe('publishToPlatform', () => {
  it('routes platform requests through the platform breaker', async () => {
    global.fetch.mockResolvedValueOnce({
      json: async () => ({ data: { id: 'tweet-123' } }),
    });

    const result = await publishToPlatform({
      platform: 'x',
      content: 'Hello platform breaker',
      post: {},
      conn: { access_token_enc: 'enc', platform_user_id: 'user-1' },
    });

    expect(mockPlatformBreakerExecute).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(
      'https://api.twitter.com/2/tweets',
      expect.objectContaining({ method: 'POST' })
    );
    expect(result).toEqual({
      postId: 'tweet-123',
      url: 'https://x.com/i/web/status/tweet-123',
    });
  });

  it('aborts slow platform requests after 15 seconds', async () => {
    jest.useFakeTimers();
    try {
      global.fetch.mockImplementation((_url, init) => new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          const err = new Error('The operation was aborted');
          err.name = 'AbortError';
          reject(err);
        });
      }));

      const promise = publishToPlatform({
        platform: 'x',
        content: 'Hello platform breaker',
        post: {},
        conn: { access_token_enc: 'enc', platform_user_id: 'user-1' },
      });

      const rejection = expect(promise).rejects.toThrow('The operation was aborted');

      await jest.advanceTimersByTimeAsync(15000);

      await rejection;
      expect(global.fetch).toHaveBeenCalledWith(
        'https://api.twitter.com/2/tweets',
        expect.objectContaining({
          signal: expect.any(Object),
        })
      );
    } finally {
      jest.useRealTimers();
    }
  });

  it('stops before fetch when the breaker is open', async () => {
    mockPlatformBreakerExecute.mockRejectedValueOnce(new Error('Circuit breaker platform-apis is OPEN'));

    await expect(publishToPlatform({
      platform: 'x',
      content: 'Hello platform breaker',
      post: {},
      conn: { access_token_enc: 'enc', platform_user_id: 'user-1' },
    })).rejects.toThrow('Circuit breaker platform-apis is OPEN');

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('refreshes expired YouTube tokens before publishing', async () => {
    global.fetch
      .mockResolvedValueOnce({ json: async () => ({ access_token: 'fresh-access', refresh_token: 'fresh-refresh', expires_in: 3600 }) })
      .mockResolvedValueOnce({ json: async () => ({ id: 'video-123' }) });

    const persistConnectionTokens = jest.fn().mockResolvedValue(undefined);

    const result = await publishToPlatform({
      platform: 'youtube',
      content: 'Hello video',
      post: { title: 'Weekly video' },
      conn: {
        access_token_enc: 'enc-access',
        refresh_token_enc: 'enc-refresh',
        token_expires_at: new Date(Date.now() - 60 * 1000).toISOString(),
        platform_user_id: 'channel-1',
      },
      persistConnectionTokens,
    });

    expect(global.fetch).toHaveBeenNthCalledWith(1, 'https://oauth2.googleapis.com/token', expect.objectContaining({ method: 'POST' }));
    expect(persistConnectionTokens).toHaveBeenCalledWith(expect.objectContaining({
      access_token_enc: 'enc:fresh-access',
      refresh_token_enc: 'enc:fresh-refresh',
      token_expires_at: expect.any(String),
    }));
    expect(result).toEqual({
      postId: 'video-123',
      url: 'https://www.youtube.com/watch?v=video-123',
    });
  });
});
