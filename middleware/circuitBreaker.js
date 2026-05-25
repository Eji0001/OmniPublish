/**
 * middleware/circuitBreaker.js — Circuit breaker pattern for external API calls
 * Prevents cascading failures; graceful degradation
 * Covers: Reliability · Resilience
 */

'use strict';

const { logger } = require('../utils/logger');

class CircuitBreaker {
  constructor(options = {}) {
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = null;
    this.nextAttemptTime = null;

    this.failureThreshold = options.failureThreshold || 5;
    this.successThreshold = options.successThreshold || 2;
    this.timeout = options.timeout || 30000;
    this.resetTimeout = options.resetTimeout || 60000;
    this.name = options.name || 'circuit-breaker';
  }

  async execute(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() >= this.nextAttemptTime) {
        this.state = 'HALF_OPEN';
        this.successCount = 0;
        logger.info(`Circuit breaker ${this.name} entering HALF_OPEN`, {});
      } else {
        throw new Error(`Circuit breaker ${this.name} is OPEN. Retry after ${new Date(this.nextAttemptTime).toISOString()}`);
      }
    }

    try {
      const result = await Promise.race([
        fn(),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`Circuit breaker ${this.name} request timeout`)), this.timeout)
        ),
      ]);

      this.recordSuccess();
      return result;
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  recordSuccess() {
    this.failureCount = 0;

    if (this.state === 'HALF_OPEN') {
      this.successCount++;
      if (this.successCount >= this.successThreshold) {
        this.state = 'CLOSED';
        logger.info(`Circuit breaker ${this.name} reset to CLOSED`, {});
      }
    }
  }

  recordFailure() {
    this.lastFailureTime = Date.now();

    if (this.state === 'HALF_OPEN') {
      this.state = 'OPEN';
      this.nextAttemptTime = Date.now() + this.resetTimeout;
      logger.warn(`Circuit breaker ${this.name} reopened after failure in HALF_OPEN`, {});
    } else if (this.state === 'CLOSED') {
      this.failureCount++;
      if (this.failureCount >= this.failureThreshold) {
        this.state = 'OPEN';
        this.nextAttemptTime = Date.now() + this.resetTimeout;
        logger.error(`Circuit breaker ${this.name} opened after ${this.failureCount} failures`, {});
      }
    }
  }

  getState() {
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime,
      nextAttemptTime: this.nextAttemptTime,
    };
  }
}

/**
 * Create circuit breakers for each external service
 */
const anthropicBreaker = new CircuitBreaker({
  name: 'anthropic-api',
  failureThreshold: 5,
  timeout: 10000,
  resetTimeout: 60000,
});

const llmBreaker = new CircuitBreaker({
  name: 'llm-api',
  failureThreshold: 5,
  timeout: 10000,
  resetTimeout: 60000,
});

const platformApisBreaker = new CircuitBreaker({
  name: 'platform-apis',
  failureThreshold: 10,
  timeout: 5000,
  resetTimeout: 30000,
});

module.exports = { CircuitBreaker, anthropicBreaker, llmBreaker, platformApisBreaker };
