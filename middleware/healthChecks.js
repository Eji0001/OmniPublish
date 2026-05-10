'use strict';

const { dbHealthCheck } = require('../config/database');
const { logger } = require('../utils/logger');

const HEALTH_CHECK_TIMEOUT = 5000;

const withTimeout = async (promise, label) => {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${label} timed out`)), HEALTH_CHECK_TIMEOUT);
    }),
  ]);
};

const healthLivenessCheck = (_req, res) => {
  res.status(200).json({ status: 'ok', time: new Date() });
};

const healthReadinessCheck = async (_req, res) => {
  try {
    const dbOk = await withTimeout(dbHealthCheck(), 'database health check');
    if (!dbOk) {
      return res.status(503).json({ status: 'not_ready', db: 'error', time: new Date() });
    }

    res.status(200).json({ status: 'ready', db: 'ok', time: new Date() });
  } catch (err) {
    logger.warn('Readiness check failed', { err: err.message });
    res.status(503).json({ status: 'not_ready', db: 'error', time: new Date() });
  }
};

module.exports = { healthLivenessCheck, healthReadinessCheck };
