/**
 * middleware/csrf.js — Double-submit cookie CSRF protection
 * State-changing requests must include both:
 *   - Cookie: csrf_token
 *   - Header: X-CSRF-Token (same value)
 */

'use strict';

const crypto = require('crypto');
const { logger } = require('../utils/logger');

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
// Include both full-path and mount-stripped variants so the check works regardless
// of whether req.path is stripped by Express's app.use() mount prefix
const CSRF_SKIP = new Set([
  '/api/v1/auth/login',            '/v1/auth/login',
  '/api/v1/auth/register',         '/v1/auth/register',
  '/api/v1/auth/forgot-password',  '/v1/auth/forgot-password',
  '/api/v1/auth/reset-password',   '/v1/auth/reset-password',
  '/api/v1/health',                '/v1/health',
  '/api/v1/health/live',           '/v1/health/live',
  '/api/v1/health/ready',          '/v1/health/ready',
  '/api/v1/auth/magic-link',             '/v1/auth/magic-link',
  '/api/v1/auth/magic-link/verify',      '/v1/auth/magic-link/verify',
  '/api/v1/auth/confirm-email',          '/v1/auth/confirm-email',
  '/api/v1/auth/oauth/exchange',         '/v1/auth/oauth/exchange',
  // Refresh is protected by httpOnly SameSite:Strict cookie — CSRF double-submit not needed
  '/api/v1/auth/refresh',                '/v1/auth/refresh',
]);

const verifyCSRF = (req, res, next) => {
  if (SAFE_METHODS.has(req.method)) return next();
  if (CSRF_SKIP.has(req.path))      return next();

  const cookieToken = req.cookies?.csrf_token;
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  try {
    const buf1 = Buffer.from(cookieToken, 'utf8');
    const buf2 = Buffer.from(headerToken, 'utf8');
    if (buf1.length !== buf2.length || !crypto.timingSafeEqual(buf1, buf2)) {
      logger.warn('CSRF mismatch', { ip: req.ip, path: req.path });
      return res.status(403).json({ error: 'CSRF token invalid' });
    }
  } catch { return res.status(403).json({ error: 'CSRF token invalid' }); }

  next();
};

const generateCSRFToken = () => crypto.randomBytes(32).toString('hex');

module.exports = { verifyCSRF, generateCSRFToken };
