'use strict';

const rateLimit = require('express-rate-limit');

const { logger } = require('../utils/logger');

let redisClient = null;

const initializeRedis = async () => {
  if (redisClient) return redisClient;

  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl) return null;

  try {
    const redis = require('redis');
    redisClient = redis.createClient({ url: redisUrl });
    redisClient.on('error', (err) => {
      logger.error('Redis client error', { err: err.message });
    });
    await redisClient.connect();
    return redisClient;
  } catch (err) {
    logger.warn('Redis rate limiting unavailable, falling back to memory store', { err: err.message });
    redisClient = null;
    return null;
  }
};

const buildLimiter = async (options = {}) => {
  const client = await initializeRedis();
  const baseOptions = {
    windowMs: options.windowMs || 15 * 60 * 1000,
    max: options.max || 100,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: options.keyGenerator || ((req) => req.ip),
    handler: options.handler,
  };

  if (!client) {
    return rateLimit(baseOptions);
  }

  try {
    const { RedisStore } = require('rate-limit-redis');
    return rateLimit({
      ...baseOptions,
      store: new RedisStore({
        sendCommand: (...args) => client.sendCommand(args),
      }),
    });
  } catch (err) {
    logger.warn('Redis store module unavailable, falling back to memory store', { err: err.message });
    return rateLimit(baseOptions);
  }
};

module.exports = { initializeRedis, buildLimiter };
