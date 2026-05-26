'use strict';

const { logger } = require('../utils/logger');

const requestLogger = (req, res, next) => {
  const start = Date.now();

  logger.debug('HTTP request started', {
    requestId: req.requestId,
    userId: req.user?.id,
    method: req.method,
    path: req.path,
    ip: req.ip,
  });

  res.on('finish', () => {
    const durationMs = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    logger[level]('HTTP request completed', {
      requestId: req.requestId,
      userId: req.user?.id,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs,
      ip: req.ip,
    });
  });

  next();
};

module.exports = { requestLogger };
