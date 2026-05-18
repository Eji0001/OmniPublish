/**
 * middleware/rateLimit.js
 * Multi-tier rate limiting: global · auth · AI/publish · media · per-user
 * Covers: OWASP A04 (Unrestricted Resource Consumption)
 */

'use strict';

const rateLimit  = require('express-rate-limit');
const slowDown   = require('express-slow-down');
const { logger } = require('../utils/logger');

const ipKey           = (req) => req.ip;
const userKey         = (req) => req.user?.id || req.ip;

const limitHandler = (req, res, _next, options) => {
  logger.warn('Rate limit exceeded', { ip: req.ip, userId: req.user?.id, path: req.path });
  res.status(429).json({
    error:      'Too many requests',
    message:    `Rate limit: ${options.max} req per ${options.windowMs / 60000} min`,
    retryAfter: Math.ceil(options.windowMs / 1000),
  });
};

const globalRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 300,
  standardHeaders: 'draft-7', legacyHeaders: false,
  keyGenerator: ipKey, handler: limitHandler,
  skip: (req) => req.path === '/api/v1/health',
});

const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 15,
  keyGenerator: ipKey, handler: limitHandler,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

const authSlowDown = slowDown({
  windowMs: 15 * 60 * 1000, delayAfter: 5,
  delayMs: (hits) => hits * 500, maxDelayMs: 5000,
  keyGenerator: ipKey,
});

const aiRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: (req) => ({ free: 10, starter: 50, pro: 200, enterprise: 1000 }[req.user?.plan] || 10),
  keyGenerator: userKey, handler: limitHandler,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

const mediaRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 50,
  keyGenerator: userKey, handler: limitHandler,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

const gdprExportRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 2,
  keyGenerator: userKey,
  handler: limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

const gdprMutationRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: userKey,
  handler: limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

const gdprStatusRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  keyGenerator: userKey,
  handler: limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

const publishRateLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,
  max: (req) => ({ free: 5, starter: 30, pro: 100, enterprise: 500 }[req.user?.plan] || 5),
  keyGenerator: userKey, handler: limitHandler,
  standardHeaders: 'draft-7', legacyHeaders: false,
});

const resetPasswordRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  keyGenerator: ipKey,
  handler: limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
});

module.exports = {
  globalRateLimiter, authRateLimiter, authSlowDown,
  aiRateLimiter, mediaRateLimiter, gdprExportRateLimiter,
  gdprMutationRateLimiter, gdprStatusRateLimiter, publishRateLimiter,
  resetPasswordRateLimiter,
};
