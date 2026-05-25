'use strict';

const express                = require('express');
const { verifyToken }        = require('../middleware/auth');
const { getAiProviderStatus } = require('../services/aiService');

const router = express.Router();

router.get('/status', verifyToken, (_req, res) => {
  res.json({ providers: getAiProviderStatus() });
});

module.exports = router;
