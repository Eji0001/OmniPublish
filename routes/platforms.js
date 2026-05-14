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
const { generateOAuthState, verifyOAuthState } = require('../middleware/oauthStateVerification');

const router = express.Router();

const isExpired = (tokenExpiresAt) => tokenExpiresAt && new Date(tokenExpiresAt) < new Date();

/* ── GET /youtube/callback — Handle OAuth callback ── */
router.get('/youtube/callback', async (req, res) => {
  try {
    const { userId, returnTo } = await verifyOAuthState(req.query.state, 'youtube');
    
    if (req.query.error) {
      logger.error('YouTube OAuth error from Google', { error: req.query.error });
      return res.redirect(`${returnTo}?platform_error=youtube_access_denied#onboarding`);
    }

    // Exchange code for tokens
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        code: req.query.code,
        redirect_uri: `${process.env.APP_URL || 'http://localhost:4000'}/api/v1/platforms/youtube/callback`,
        grant_type: 'authorization_code'
      })
    });
    
    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);

    // Get YouTube Channel Info
    const channelRes = await fetch('https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true', {
      headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
    });
    const channelData = await channelRes.json();
    if (channelData.error) throw new Error(channelData.error.message);

    const channelId = channelData.items?.[0]?.id || 'unknown';
    const channelTitle = channelData.items?.[0]?.snippet?.title || 'YouTube Channel';
    const expiresAt = tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : null;

    // Upsert platform connection
    await supabase.from('platform_connections').upsert({
      user_id:           userId,
      platform:          'youtube',
      platform_user_id:  channelId,
      platform_username: channelTitle,
      access_token_enc:  encrypt(tokenData.access_token),
      refresh_token_enc: tokenData.refresh_token ? encrypt(tokenData.refresh_token) : null,
      token_expires_at:  expiresAt,
      is_active:         true,
      connected_at:      new Date(),
    }, { onConflict: 'user_id,platform' });

    logger.info('YouTube connected successfully via OAuth', { userId });
    res.redirect(`${returnTo}?platform_success=youtube#onboarding`);
  } catch (err) {
    logger.error('YouTube callback error', { err: err.message });
    res.redirect(`/?platform_error=youtube_callback_failed#onboarding`);
  }
});

// Authenticated routes below
router.use(verifyToken);

/* ── GET /platforms — list connected platforms ── */
router.get('/', async (req, res) => {
  const { data, error } = await supabase.from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Failed to fetch platforms' });
  res.json({ platforms: data });
});

/* ── GET /platforms/youtube/auth — Initiate OAuth ── */
router.get('/youtube/auth', async (req, res) => {
  try {
    const returnTo = req.query.returnTo || (process.env.APP_URL || 'http://localhost:4000');
    const { state } = await generateOAuthState('youtube', req.user.id, returnTo);
    
    const oauthUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    oauthUrl.searchParams.append('client_id', process.env.GOOGLE_CLIENT_ID);
    oauthUrl.searchParams.append('redirect_uri', `${process.env.APP_URL || 'http://localhost:4000'}/api/v1/platforms/youtube/callback`);
    oauthUrl.searchParams.append('response_type', 'code');
    oauthUrl.searchParams.append('scope', 'https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly');
    oauthUrl.searchParams.append('access_type', 'offline');
    oauthUrl.searchParams.append('prompt', 'consent');
    oauthUrl.searchParams.append('state', state);

    res.json({ url: oauthUrl.toString() });
  } catch (err) {
    logger.error('Failed to generate YouTube auth URL', { err: err.message });
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
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
