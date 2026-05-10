/**
 * services/platformRetryService.js — Enhanced platform publishing with retry logic and error classification
 * Covers: Resilience · Error handling · Exponential backoff
 */

'use strict';

const { logger } = require('../utils/logger');

/**
 * Error classification for platform APIs
 */
const classifyPlatformError = (error, platform) => {
  const message = error.message || '';
  const statusCode = error.statusCode || error.status;

  // Transient errors (retryable)
  const transientPatterns = [
    /rate.limit|too.many.request/i,
    /throttl/i,
    /timeout|timed.out|ETIMEDOUT/i,
    /ECONNRESET|ECONNREFUSED|EHOSTUNREACH/i,
    /503|504|502|429/,
    /temporary|try.again/i,
    /service.unavailable|temporarily/i,
  ];

  const isTransient = transientPatterns.some(pattern => pattern.test(message));

  // Permanent errors (do not retry)
  const permanentPatterns = [
    /invalid.token|unauthorized|403|401/i,
    /not.found|404/i,
    /invalid.request|400|422/i,
    /bad.request/i,
    /cannot|not.permitted|permission.denied/i,
  ];

  const isPermanent = permanentPatterns.some(pattern => pattern.test(message));

  return {
    isTransient,
    isPermanent: isPermanent || statusCode === 400 || statusCode === 401 || statusCode === 403 || statusCode === 404,
    code: extractErrorCode(error, platform),
    message: sanitizeErrorMessage(message),
  };
};

/**
 * Extract structured error code from platform response
 */
const extractErrorCode = (error, platform) => {
  if (!error) return `${platform}_UNKNOWN_ERROR`;

  const message = error.message || '';
  if (message.includes('Invalid token')) return `${platform}_INVALID_TOKEN`;
  if (message.includes('Rate limit')) return `${platform}_RATE_LIMITED`;
  if (message.includes('not found')) return `${platform}_NOT_FOUND`;
  if (message.includes('timeout')) return `${platform}_TIMEOUT`;

  return `${platform}_ERROR`;
};

/**
 * Remove sensitive info from error messages
 */
const sanitizeErrorMessage = (msg) => {
  return (msg || '')
    .replace(/[a-zA-Z0-9+/=]{40,}/g, '[REDACTED_TOKEN]')
    .substring(0, 200);
};

/**
 * Exponential backoff with jitter
 */
const getBackoffDelay = (attempt, baseDelay = 1000, maxDelay = 30000) => {
  const exponential = baseDelay * Math.pow(2, Math.min(attempt, 5));
  const jitter = Math.random() * 0.1 * exponential;
  return Math.min(exponential + jitter, maxDelay);
};

/**
 * Retry wrapper for platform publish operations
 */
const publishWithRetry = async (
  publishFn,
  platform,
  options = {}
) => {
  const maxRetries = options.maxRetries || 3;
  const baseDelay = options.baseDelay || 1000;
  let lastError;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const result = await publishFn();
      logger.info('Platform publish succeeded', { platform, attempt });
      return result;
    } catch (error) {
      lastError = error;
      const classification = classifyPlatformError(error, platform);

      logger.warn('Platform publish failed', {
        platform,
        attempt: attempt + 1,
        error: classification.message,
        isTransient: classification.isTransient,
        code: classification.code,
      });

      // Don't retry permanent errors
      if (classification.isPermanent) {
        error.isRetryable = false;
        error.code = classification.code;
        error.platform = platform;
        throw error;
      }

      // Don't retry on last attempt
      if (attempt === maxRetries - 1) {
        error.isRetryable = true;
        error.code = classification.code;
        error.platform = platform;
        throw error;
      }

      // Wait before retrying
      const delay = getBackoffDelay(attempt, baseDelay);
      logger.debug(`Retrying ${platform} after ${delay}ms`, { attempt: attempt + 1 });
      await new Promise(r => setTimeout(r, delay));
    }
  }

  throw lastError;
};

/**
 * Normalize platform responses to consistent format
 */
const normalizePlatformResponse = (response, platform) => {
  // Each platform handler should return: { postId, url }
  if (!response || !response.postId || !response.url) {
    throw new Error(`Invalid response from ${platform} handler`);
  }
  return response;
};

module.exports = {
  classifyPlatformError,
  extractErrorCode,
  sanitizeErrorMessage,
  getBackoffDelay,
  publishWithRetry,
  normalizePlatformResponse,
};
