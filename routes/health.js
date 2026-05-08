/**
 * routes/health.js — Liveness and readiness probes
 */

'use strict';

const express           = require('express');
const { dbHealthCheck } = require('../config/database');

const router = express.Router();

router.get('/live',  (_req, res) => res.json({ status: 'ok', time: new Date() }));

router.get('/ready', async (_req, res) => {
  const dbOk   = await dbHealthCheck();
  const status = dbOk ? 'ready' : 'not_ready';
  res.status(dbOk ? 200 : 503).json({ status, db: dbOk ? 'ok' : 'error', time: new Date() });
});

// Default /health route
router.get('/', (_req, res) => res.json({ status: 'ok', service: 'OmniPublish API', version: '2.0.0', time: new Date() }));

module.exports = router;
