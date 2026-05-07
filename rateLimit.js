/**
 * middleware/rateLimit.js
 * Multi-tier rate limiting strategy:
 *   - Global API limiter (all routes)
 *   - Auth-specific strict limiter (brute-force protection)
 *   - AI/publish limiter (expensive operations)
 *   - Per-user authenticated limiter (plan-aware)
 * Covers: OWASP A04 (Unrestricted Resource Consumption)
 */

'use strict';

const rateLimit  = require('express-rate-limit');
const slowDown   = require('express-slow-down');
const { logger } = require('../utils/logger');

/* ── Key generators ─────────────────────── */

// IP-based key (fallback for unauthenticated)
const ipKey = (req) => req.ip;

// User-ID key for authenticated routes
const userKey = (req) => req.user?.id || req.ip;

// Composite key: user + endpoint (fine-grained)
const userEndpointKey = (req) => `${req.user?.id || req.ip}:${req.route?.path || req.path}`;

/* ── On-limit handler ────────────────────── */
const limitHandler = (req, res, _next, options) => {
  logger.warn('Rate limit exceeded', {
    ip:       req.ip,
    userId:   req.user?.id,
    path:     req.path,
    limit:    options.max,
    windowMs: options.windowMs,
  });
  res.status(429).json({
    error:   'Too many requests',
    message: `Rate limit: ${options.max} requests per ${options.windowMs / 60000} min`,
    retryAfter: Math.ceil(options.windowMs / 1000),
  });
};

/* ── TIER 1 — Global API limiter ─────────── */
const globalRateLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,    // 15 min
  max:             300,                // 300 req / IP / window
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
  keyGenerator:    ipKey,
  handler:         limitHandler,
  skip: (req) => req.path === '/api/v1/health',
});

/* ── TIER 2 — Auth strict limiter ───────── */
// Protects login / register / reset-password from brute-force
const authRateLimiter = rateLimit({
  windowMs:     15 * 60 * 1000,   // 15 min
  max:          15,                 // 15 attempts
  keyGenerator: ipKey,
  handler:      limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
});

// Progressive slowdown before hard limit hits
const authSlowDown = slowDown({
  windowMs:           15 * 60 * 1000,
  delayAfter:         5,            // start slowing after 5 attempts
  delayMs:            (hits) => hits * 500,  // +500ms per excess attempt
  maxDelayMs:         5000,
  keyGenerator:       ipKey,
});

/* ── TIER 3 — AI / Publish limiter ─────── */
// Expensive compute routes; plan-aware
const aiRateLimiter = rateLimit({
  windowMs:     60 * 60 * 1000,    // 1 hour
  max:          (req) => {
    const plan = req.user?.plan || 'free';
    return { free: 10, starter: 50, pro: 200, enterprise: 1000 }[plan] || 10;
  },
  keyGenerator: userKey,
  handler:      limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
  message: 'AI request quota exceeded for your plan',
});

/* ── TIER 4 — Media upload limiter ─────── */
const mediaRateLimiter = rateLimit({
  windowMs:     60 * 60 * 1000,   // 1 hour
  max:          50,
  keyGenerator: userKey,
  handler:      limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
});

/* ── TIER 5 — Publish limiter ───────────── */
const publishRateLimiter = rateLimit({
  windowMs: 24 * 60 * 60 * 1000,   // 24 hours
  max: (req) => {
    const plan = req.user?.plan || 'free';
    return { free: 5, starter: 30, pro: 100, enterprise: 500 }[plan] || 5;
  },
  keyGenerator: userKey,
  handler:      limitHandler,
  standardHeaders: 'draft-7',
  legacyHeaders:   false,
});

module.exports = {
  globalRateLimiter,
  authRateLimiter,
  authSlowDown,
  aiRateLimiter,
  mediaRateLimiter,
  publishRateLimiter,
};
