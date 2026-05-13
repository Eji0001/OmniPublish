/**
 * routes/platforms.js — OAuth platform connection management
 */

'use strict';

const express         = require('express');
const { supabase }    = require('../config/database');
const { verifyToken } = require('../middleware/auth');
const { validateBody } = require('../middleware/sanitizer');
const { encrypt }     = require('../utils/encryption');
const { logger }      = require('../utils/logger');

const router = express.Router();
router.use(verifyToken);

const isExpired = (tokenExpiresAt) => tokenExpiresAt && new Date(tokenExpiresAt) < new Date();

/* ── GET /platforms — list connected platforms ── */
router.get('/', async (req, res) => {
  const { data, error } = await supabase.from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Failed to fetch platforms' });
  res.json({ platforms: data });
});

/* ── POST /platforms/connect — store OAuth tokens ── */
router.post('/connect', validateBody('platformConnection'), async (req, res) => {
  const { platform, accessToken, refreshToken, platformUserId, platformUsername, expiresAt } = req.body;

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

/* ── POST /platforms/:id/verify — verify connection status ── */
router.post('/:id/verify', async (req, res) => {
  const { data: connection, error } = await supabase.from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .single();

  if (error || !connection) return res.status(404).json({ error: 'Connection not found' });

  const expired = isExpired(connection.token_expires_at);
  const connectionStatus = connection.is_active
    ? (expired ? 'expired' : 'active')
    : 'inactive';

  res.json({
    connection: {
      ...connection,
      connection_status: connectionStatus,
      token_valid: connection.is_active && !expired,
    },
  });
});

/* ── PATCH /platforms/:id — toggle connection on/off ── */
router.patch('/:id', async (req, res) => {
  const { is_active } = req.body || {};
  if (typeof is_active !== 'boolean') return res.status(422).json({ error: 'is_active is required' });

  const { data: connection, error } = await supabase.from('platform_connections')
    .update({ is_active })
    .eq('id', req.params.id)
    .eq('user_id', req.user.id)
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .single();

  if (error || !connection) return res.status(404).json({ error: 'Connection not found' });

  res.json({ connection });
});

/* ── DELETE /platforms/:id — disconnect platform ── */
router.delete('/:id', async (req, res) => {
  const { error } = await supabase.from('platform_connections')
    .update({ is_active: false }).eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(404).json({ error: 'Connection not found' });
  res.status(204).send();
});

module.exports = router;
