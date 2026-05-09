'use strict';

const crypto     = require('crypto');
const { logger } = require('../utils/logger');

const requireApiKey = (req, res, next) => {
  const provided = req.headers['x-api-key'];
  const expected = process.env.ADMIN_API_KEY;

  if (!expected) {
    logger.error('ADMIN_API_KEY env var not set');
    return res.status(500).json({ error: 'API key authentication not configured' });
  }
  if (!provided) {
    return res.status(401).json({ error: 'X-Api-Key header required', code: 'API_KEY_MISSING' });
  }

  // Pad both to same length before timing-safe compare to avoid length leakage
  const maxLen = Math.max(provided.length, expected.length);
  const a = Buffer.alloc(maxLen, 0);
  const b = Buffer.alloc(maxLen, 0);
  Buffer.from(provided).copy(a);
  Buffer.from(expected).copy(b);

  const valid = crypto.timingSafeEqual(a, b) && provided === expected;
  if (!valid) {
    logger.warn('Invalid API key attempt', { ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Invalid API key', code: 'API_KEY_INVALID' });
  }

  req.apiKeyAuth = true;
  req.user = { id: 'api-service', role: 'admin', plan: 'enterprise' };
  next();
};

// Accepts either a valid JWT (via verifyToken) or a valid API key
const requireJwtOrApiKey = (verifyToken) => async (req, res, next) => {
  const hasApiKey = !!req.headers['x-api-key'];
  const hasBearer = req.headers['authorization']?.startsWith('Bearer ');

  if (hasApiKey)  return requireApiKey(req, res, next);
  if (hasBearer)  return verifyToken(req, res, next);

  return res.status(401).json({
    error: 'Authentication required',
    code:  'AUTH_REQUIRED',
    hint:  'Provide Authorization: Bearer <token> or X-Api-Key: <key>',
  });
};

module.exports = { requireApiKey, requireJwtOrApiKey };
