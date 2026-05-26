'use strict';

const { EventEmitter } = require('events');

jest.mock('../../utils/logger', () => ({
  logger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

const { logger } = require('../../utils/logger');
const { requestLogger } = require('../../middleware/requestLogger');

beforeEach(() => jest.clearAllMocks());

describe('requestLogger', () => {
  it('logs request start and successful completion with structured context', () => {
    const res = new EventEmitter();
    res.statusCode = 200;

    const req = {
      method: 'GET',
      path: '/api/v1/dashboard',
      ip: '127.0.0.1',
      requestId: 'req_123',
      user: { id: 'user-1' },
    };

    const next = jest.fn();

    requestLogger(req, res, next);
    res.emit('finish');

    expect(next).toHaveBeenCalled();
    expect(logger.debug).toHaveBeenCalledWith('HTTP request started', expect.objectContaining({
      requestId: 'req_123',
      userId: 'user-1',
      method: 'GET',
      path: '/api/v1/dashboard',
    }));
    expect(logger.info).toHaveBeenCalledWith('HTTP request completed', expect.objectContaining({
      requestId: 'req_123',
      userId: 'user-1',
      method: 'GET',
      path: '/api/v1/dashboard',
      status: 200,
      durationMs: expect.any(Number),
    }));
  });

  it('logs failed responses at error level', () => {
    const res = new EventEmitter();
    res.statusCode = 500;

    const req = {
      method: 'POST',
      path: '/api/v1/publish',
      ip: '10.0.0.1',
      requestId: 'req_456',
    };

    requestLogger(req, res, jest.fn());
    res.emit('finish');

    expect(logger.error).toHaveBeenCalledWith('HTTP request completed', expect.objectContaining({
      requestId: 'req_456',
      method: 'POST',
      path: '/api/v1/publish',
      status: 500,
    }));
  });
});
