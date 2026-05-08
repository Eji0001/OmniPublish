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
const CSRF_SKIP    = new Set(['/api/v1/auth/login', '/api/v1/auth/register', '/api/v1/health']);

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
