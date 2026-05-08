/**
 * middleware/errorHandler.js — Centralised error formatting
 * Never leaks stack traces to clients in production.
 */

'use strict';

const { logger } = require('../utils/logger');

const errorHandler = (err, req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  const isProd  = process.env.NODE_ENV === 'production';

  logger.error('Unhandled error', {
    status, message: err.message, stack: err.stack,
    path: req.path, method: req.method,
    requestId: req.requestId, userId: req.user?.id,
  });

  if (err.message?.includes('CORS'))
    return res.status(403).json({ error: 'CORS policy violation' });
  if (err.type === 'entity.parse.failed')
    return res.status(400).json({ error: 'Invalid JSON body' });
  if (err.type === 'entity.too.large')
    return res.status(413).json({ error: 'Request body too large' });

  const body = {
    error:     isProd && status === 500 ? 'Internal server error' : err.message,
    requestId: req.requestId,
    ...(isProd ? {} : { stack: err.stack }),
  };
  if (err.errors) body.errors = err.errors;

  res.status(status).json(body);
};

module.exports = { errorHandler };
