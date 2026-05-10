/**
 * middleware/oauthStateVerification.js — OAuth state parameter verification for CSRF protection
 * Covers: OWASP A07 (Cross-Site Request Forgery protection)
 */

'use strict';

const { v4: uuidv4 } = require('uuid');
const { supabase } = require('../config/database');
const { logger } = require('../utils/logger');

/**
 * generateOAuthState — Create and store OAuth state token
 * State tokens prevent CSRF attacks on OAuth redirects
 */
const generateOAuthState = async (platform, userId = null) => {
  const state = uuidv4();
  const nonce = require('crypto').randomBytes(32).toString('hex');

  try {
    await supabase
      .from('oauth_states')
      .insert({
        state,
        user_id: userId,
        platform,
        nonce,
        expires_at: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
      });

    logger.debug('OAuth state created', { platform, userId });
    return { state, nonce };
  } catch (err) {
    logger.error('Failed to store OAuth state', { err: err.message });
    throw new Error('OAuth initialization failed');
  }
};

/**
 * verifyOAuthState — Validate state parameter and return stored values
 * Also performs cleanup of used states
 */
const verifyOAuthState = async (state, platform) => {
  if (!state || typeof state !== 'string') {
    logger.warn('OAuth state verification: missing state parameter');
    throw new Error('Invalid state parameter');
  }

  try {
    // Retrieve state record
    const { data: record, error } = await supabase
      .from('oauth_states')
      .select('user_id, nonce')
      .eq('state', state)
      .eq('platform', platform)
      .gt('expires_at', new Date().toISOString())
      .single();

    if (error || !record) {
      logger.warn('OAuth state verification failed', { state: state.slice(0, 8), platform, error: error?.message });
      throw new Error('Invalid or expired state parameter');
    }

    // Delete the used state (one-time use)
    await supabase
      .from('oauth_states')
      .delete()
      .eq('state', state);

    logger.info('OAuth state verified', { platform, userId: record.user_id });
    return { userId: record.user_id, nonce: record.nonce };
  } catch (err) {
    logger.error('OAuth state verification error', { err: err.message });
    throw err;
  }
};

/**
 * cleanupExpiredOAuthStates — Periodic cleanup of expired state records
 * Call from scheduler service every hour
 */
const cleanupExpiredOAuthStates = async () => {
  try {
    const { error } = await supabase
      .from('oauth_states')
      .delete()
      .lt('expires_at', new Date().toISOString());

    if (error) {
      logger.error('OAuth state cleanup error', { err: error.message });
    } else {
      logger.debug('OAuth state cleanup completed');
    }
  } catch (err) {
    logger.error('OAuth state cleanup failed', { err: err.message });
  }
};

module.exports = {
  generateOAuthState,
  verifyOAuthState,
  cleanupExpiredOAuthStates,
};
