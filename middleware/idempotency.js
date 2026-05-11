/**
 * middleware/idempotency.js — Idempotency key tracking for state-changing operations
 * Prevents duplicate side-effects on retried requests
 * Covers: OWASP A04 (Unrestricted Resource Consumption)
 */

'use strict';

const { supabase } = require('../config/database');
const { logger } = require('../utils/logger');

const IDEMPOTENT_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
// Express strips the `/api/` mount prefix here, so include the post-mount path.
const IDEMPOTENT_PATHS = ['/publish', '/v1/auth/reset-password', '/api/v1/auth/reset-password'];

/**
 * idempotencyMiddleware — Check for cached idempotency result
 * If request already processed, return cached response
 */
const idempotencyMiddleware = async (req, res, next) => {
  // Only enforce for state-changing methods on certain paths
  if (!IDEMPOTENT_METHODS.has(req.method)) return next();
  if (!IDEMPOTENT_PATHS.some(path => req.path.includes(path))) return next();

  const idempotencyKey = req.headers['idempotency-key'];
  if (!idempotencyKey) {
    return res.status(400).json({
      error: 'Idempotency-Key header required',
      code: 'IDEMPOTENCY_KEY_MISSING',
      hint: 'Provide a unique UUID in the Idempotency-Key header',
    });
  }

  // Validate format
  if (!/^[a-f0-9-]{36}$/.test(idempotencyKey)) {
    return res.status(400).json({
      error: 'Idempotency-Key must be a valid UUID',
      code: 'IDEMPOTENCY_KEY_INVALID',
    });
  }

  try {
    // Check if this idempotency key has a cached result
    const { data: cached } = await supabase
      .from('idempotency_tokens')
      .select('response, created_at')
      .eq('idempotency_key', idempotencyKey)
      .eq('user_id', req.user?.id || 'anonymous')
      .single();

    if (cached) {
      // Return cached response
      logger.info('Idempotent request (cached)', {
        idempotencyKey,
        userId: req.user?.id,
        age: Date.now() - new Date(cached.created_at).getTime(),
      });
      return res.status(200).json(JSON.parse(cached.response));
    }
  } catch (err) {
    // Not found is expected; other errors log but don't block
    if (err.code !== 'PGRST116') {
      logger.warn('Idempotency check error', { err: err.message });
    }
  }

  // Store original res.json to intercept response
  const originalJson = res.json.bind(res);
  res.json = function (body) {
    // Cache the response if request succeeded (2xx)
    if (res.statusCode >= 200 && res.statusCode < 300) {
      supabase
        .from('idempotency_tokens')
        .insert({
          idempotency_key: idempotencyKey,
          user_id: req.user?.id || 'anonymous',
          response: JSON.stringify(body),
          expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24h
        })
        .then(({ error: dbErr }) => {
          if (dbErr) logger.warn('Failed to cache idempotency result', { err: dbErr.message });
        })
        .catch(err => logger.warn('Failed to cache idempotency result', { err: err.message }));
    }
    return originalJson(body);
  };

  next();
};

module.exports = { idempotencyMiddleware };
