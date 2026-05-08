/**
 * routes/platforms.js — OAuth platform connection management
 */

'use strict';

const express         = require('express');
const { supabase }    = require('../config/database');
const { verifyToken } = require('../middleware/auth');
const { encrypt }     = require('../utils/encryption');
const { logger }      = require('../utils/logger');

const router = express.Router();
router.use(verifyToken);

/* ── GET /platforms — list connected platforms ── */
router.get('/', async (req, res) => {
  const { data, error } = await supabase.from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Failed to fetch platforms' });
  res.json({ platforms: data });
});

/* ── POST /platforms/connect — store OAuth tokens ── */
router.post('/connect', async (req, res) => {
  const { platform, accessToken, refreshToken, platformUserId, platformUsername, expiresAt } = req.body;
  if (!platform || !accessToken) return res.status(422).json({ error: 'platform and accessToken required' });

  const { data, error } = await supabase.from('platform_connections').upsert({
    user_id:           req.user.id,
    platform,
    platform_user_id:  platformUserId,
    platform_username: platformUsername,
    access_token_enc:  encrypt(accessToken),
    refresh_token_enc: refreshToken ? encrypt(refreshToken) : null,
    token_expires_at:  expiresAt || null,
    is_active:         true,
    connected_at:      new Date(),
  }, { onConflict: 'user_id,platform' }).select('id, platform, platform_username').single();

  if (error) return res.status(500).json({ error: 'Failed to save platform connection' });
  logger.info('Platform connected', { userId: req.user.id, platform });
  res.status(201).json({ connection: data });
});

/* ── DELETE /platforms/:id — disconnect platform ── */
router.delete('/:id', async (req, res) => {
  const { error } = await supabase.from('platform_connections')
    .update({ is_active: false }).eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(404).json({ error: 'Connection not found' });
  res.status(204).send();
});

module.exports = router;
