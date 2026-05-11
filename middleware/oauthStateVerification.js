/**
 * middleware/oauthStateVerification.js — OAuth state parameter verification for CSRF protection
 * Covers: OWASP A07 (Cross-Site Request Forgery protection)
 */

'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { JWT_CONFIG } = require('../config/security');
const { logger } = require('../utils/logger');

/**
 * generateOAuthState — Create a signed OAuth state token
 * State tokens prevent CSRF attacks on OAuth redirects without DB storage
 */
const generateOAuthState = async (platform, userId = null) => {
  const nonce = crypto.randomBytes(32).toString('hex');
  const state = jwt.sign(
    { platform, userId, nonce },
    JWT_CONFIG.accessSecret,
    { expiresIn: '15m', issuer: JWT_CONFIG.issuer, audience: JWT_CONFIG.audience, algorithm: JWT_CONFIG.algorithm }
  );
  logger.debug('OAuth state created', { platform, userId });
  return { state, nonce };
};

/**
 * verifyOAuthState — Validate a signed state parameter and return its payload
 */
const verifyOAuthState = async (state, platform) => {
  if (!state || typeof state !== 'string') {
    logger.warn('OAuth state verification: missing state parameter');
    throw new Error('Invalid state parameter');
  }

  try {
    const record = jwt.verify(state, JWT_CONFIG.accessSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
    });

    if (record.platform !== platform) {
      logger.warn('OAuth state verification failed', { platform, error: 'Platform mismatch' });
      throw new Error('Invalid or expired state parameter');
    }

    logger.info('OAuth state verified', { platform, userId: record.userId });
    return { userId: record.userId || null, nonce: record.nonce };
  } catch (err) {
    logger.error('OAuth state verification error', { err: err.message });
    throw err;
  }
};

/**
 * cleanupExpiredOAuthStates — No-op with stateless OAuth state tokens
 */
const cleanupExpiredOAuthStates = async () => {
  logger.debug('OAuth state cleanup skipped (stateless tokens)');
};

module.exports = {
  generateOAuthState,
  verifyOAuthState,
  cleanupExpiredOAuthStates,
};
