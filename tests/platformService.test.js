'use strict';

const mockDecrypt = jest.fn(() => 'access-token');
const mockPlatformBreakerExecute = jest.fn(async (fn) => fn());

jest.mock('../middleware/circuitBreaker', () => ({
  anthropicBreaker: { execute: jest.fn(async (fn) => fn()) },
  platformApisBreaker: { execute: mockPlatformBreakerExecute },
}));

jest.mock('../utils/encryption', () => ({
  decrypt: mockDecrypt,
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
});
