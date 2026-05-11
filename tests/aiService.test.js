'use strict';

const mockAnthropicMessagesCreate = jest.fn();
const mockAnthropicBreakerExecute = jest.fn(async (fn) => fn());

jest.mock('../middleware/circuitBreaker', () => ({
  anthropicBreaker: { execute: mockAnthropicBreakerExecute },
  platformApisBreaker: { execute: jest.fn(async (fn) => fn()) },
}));

jest.mock('@anthropic-ai/sdk', () => jest.fn().mockImplementation(() => ({
  messages: { create: mockAnthropicMessagesCreate },
})));

jest.mock('../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { aiAdaptContent } = require('../services/aiService');

beforeEach(() => {
  jest.clearAllMocks();
  mockAnthropicMessagesCreate.mockResolvedValue({
    content: [{ type: 'text', text: '{"x":"breaker-wired"}' }],
  });
  mockAnthropicBreakerExecute.mockImplementation(async (fn) => fn());
});

describe('aiAdaptContent', () => {
  it('routes Claude calls through the anthropic breaker', async () => {
    const result = await aiAdaptContent({
      content: 'Hello world',
      platforms: ['x'],
      userId: 'user-1',
    });

    expect(mockAnthropicBreakerExecute).toHaveBeenCalledTimes(1);
    expect(mockAnthropicMessagesCreate).toHaveBeenCalledTimes(1);
    expect(result).toEqual({ x: 'breaker-wired' });
  });

  it('falls back when the breaker blocks Anthropic', async () => {
    mockAnthropicBreakerExecute.mockRejectedValueOnce(new Error('Circuit breaker anthropic-api is OPEN'));

    const result = await aiAdaptContent({
      content: 'Hello breaker',
      platforms: ['x'],
      userId: 'user-2',
    });

    expect(mockAnthropicMessagesCreate).not.toHaveBeenCalled();
    expect(result).toEqual({ x: 'Hello breaker' });
  });
});
