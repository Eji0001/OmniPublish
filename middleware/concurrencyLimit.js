'use strict';

const { logger } = require('../utils/logger');

class ConcurrencyLimiter {
  constructor(options = {}) {
    this.defaultLimit = options.defaultLimit || 5;
    this.connections = new Map();
  }

  middleware(limit = this.defaultLimit) {
    return (req, res, next) => {
      const userId = req.user?.id || req.ip;
      const key = `user:${userId}`;
      const current = (this.connections.get(key) || 0) + 1;

      if (current > limit) {
        logger.warn('Concurrency limit exceeded', { userId, current, limit, path: req.path });
        return res.status(429).json({
          error: 'Too many concurrent requests',
          code: 'CONCURRENCY_LIMIT_EXCEEDED',
          current,
          limit,
        });
      }

      this.connections.set(key, current);

      let released = false;
      const release = () => {
        if (released) return;
        released = true;

        const nextCount = (this.connections.get(key) || 1) - 1;
        if (nextCount <= 0) {
          this.connections.delete(key);
        } else {
          this.connections.set(key, nextCount);
        }
      };

      res.on('finish', release);
      res.on('close', release);
      next();
    };
  }

  getConnections(userId) {
    return this.connections.get(`user:${userId}`) || 0;
  }

  getAllConnections() {
    return Array.from(this.connections.entries()).map(([key, count]) => ({ key, count }));
  }
}

const limiter = new ConcurrencyLimiter({ defaultLimit: 5 });

module.exports = { ConcurrencyLimiter, limiter };
