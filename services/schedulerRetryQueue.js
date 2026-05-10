'use strict';

const { supabase } = require('../config/database');
const { logger } = require('../utils/logger');

class RetryQueue {
  constructor(options = {}) {
    this.maxRetries = options.maxRetries || 5;
    this.baseDelayMs = options.baseDelayMs || 1000;
    this.maxDelayMs = options.maxDelayMs || 5 * 60 * 1000;
  }

  getBackoffDelay(attempt) {
    const exponential = this.baseDelayMs * Math.pow(2, Math.min(attempt, 5));
    const jitter = Math.random() * 0.1 * exponential;
    return Math.min(exponential + jitter, this.maxDelayMs);
  }

  async enqueue(item) {
    try {
      const { error } = await supabase.from('retry_queue').insert({
        operation_type: item.type,
        payload: item.payload,
        attempt: 0,
        max_retries: item.maxRetries || this.maxRetries,
        status: 'pending',
        next_retry_at: new Date(),
      });

      if (error) throw error;
      logger.info('Retry queue item added', { type: item.type });
    } catch (err) {
      logger.error('Failed to enqueue retry item', { err: err.message, type: item.type });
    }
  }

  async processQueue(handlers) {
    const { data: items, error } = await supabase
      .from('retry_queue')
      .select('*')
      .eq('status', 'pending')
      .lte('next_retry_at', new Date().toISOString())
      .limit(20);

    if (error) {
      logger.error('Failed to load retry queue', { err: error.message });
      return;
    }
    if (!items?.length) return;

    for (const item of items) {
      const handler = handlers[item.operation_type];
      if (!handler) {
        await this.markFailed(item, 'No handler registered for retry operation');
        continue;
      }

      try {
        const payload = typeof item.payload === 'string' ? JSON.parse(item.payload) : item.payload;
        await handler(payload, item);
        await supabase.from('retry_queue').update({
          status: 'completed',
          completed_at: new Date(),
          last_error: null,
        }).eq('id', item.id);
      } catch (err) {
        await this.reschedule(item, err);
      }
    }
  }

  async reschedule(item, err) {
    const attempt = (item.attempt || 0) + 1;
    if (attempt >= (item.max_retries || this.maxRetries)) {
      await this.markFailed(item, err.message);
      return;
    }

    const delayMs = this.getBackoffDelay(attempt);
    await supabase.from('retry_queue').update({
      attempt,
      last_error: err.message,
      next_retry_at: new Date(Date.now() + delayMs),
    }).eq('id', item.id);
  }

  async markFailed(item, reason) {
    await supabase.from('retry_queue').update({
      status: 'failed',
      last_error: reason,
      failure_reason: reason,
      failed_at: new Date(),
    }).eq('id', item.id);
  }
}

const retryQueue = new RetryQueue();

module.exports = { RetryQueue, retryQueue };
