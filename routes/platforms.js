/**
 * routes/platforms.js — OAuth platform connection management
 */

'use strict';

const crypto         = require('crypto');
const express         = require('express');
const { supabase }    = require('../config/database');
const { verifyToken } = require('../middleware/auth');
const { validateBody } = require('../middleware/sanitizer');
const { encrypt }     = require('../utils/encryption');
const { logger }      = require('../utils/logger');
const { generateOAuthState, verifyOAuthState } = require('../middleware/oauthStateVerification');

const router = express.Router();
const getDb = (req) => req.db || supabase;

const isProd = process.env.NODE_ENV === 'production';
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

const isExpired = (tokenExpiresAt) => tokenExpiresAt && new Date(tokenExpiresAt) < new Date();
const base64Url = (value) => value.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const getSafeReturnTo = (candidate) => {
  const fallback = process.env.FRONTEND_URL || process.env.APP_URL || 'http://localhost:4000';

  // No allowlist configured — never trust user-supplied redirect targets
  if (!ALLOWED_ORIGINS.length) return fallback;

  try {
    const { origin } = new URL(candidate || fallback);
    if (ALLOWED_ORIGINS.includes(origin)) return origin;
  } catch {
    // fall through to safe fallback
  }

  return fallback;
};

const generatePkcePair = () => {
  const verifier = base64Url(crypto.randomBytes(32));
  const challenge = base64Url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
};

const getClientIdParam = (provider) => provider.clientIdParam || 'client_id';
const getTokenClientIdParam = (provider) => provider.tokenClientIdParam || provider.clientIdParam || 'client_id';

const OAUTH_PROVIDERS = {
  youtube: {
    authUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    profileUrl: 'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true',
    scopes: 'https://www.googleapis.com/auth/youtube.upload https://www.googleapis.com/auth/youtube.readonly',
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    pkce: true,
    extractProfile: (data) => ({
      id: data.items?.[0]?.id || 'unknown',
      username: data.items?.[0]?.snippet?.title || 'YouTube Channel'
    })
  },
  x: {
    authUrl: 'https://x.com/i/oauth2/authorize',
    tokenUrl: 'https://api.twitter.com/2/oauth2/token',
    profileUrl: 'https://api.twitter.com/2/users/me',
    scopes: 'tweet.read tweet.write users.read offline.access',
    clientId: process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID,
    clientSecret: process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET,
    pkce: true,
    useBasicAuthForToken: true,
    extractProfile: (data) => ({
      id: data.data?.id || 'unknown',
      username: data.data?.username || 'X Account'
    })
  },
  linkedin: {
    authUrl: 'https://www.linkedin.com/oauth/v2/authorization',
    tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
    profileUrl: 'https://api.linkedin.com/v2/userinfo',
    scopes: 'w_member_social profile openid email',
    clientId: process.env.LINKEDIN_CLIENT_ID,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
    extractProfile: (data) => ({
      id: data.sub || 'unknown',
      username: data.name || 'LinkedIn User'
    })
  },
  facebook: {
    authUrl: 'https://www.facebook.com/v19.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v19.0/oauth/access_token',
    profileUrl: 'https://graph.facebook.com/me?fields=id,name',
    scopes: 'pages_show_list,pages_read_engagement,pages_manage_posts,publish_video',
    clientId: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    extractProfile: (data) => ({
      id: data.id || 'unknown',
      username: data.name || 'Facebook User'
    })
  },
  instagram: {
    // Instagram Graph API via Facebook Login (Basic Display API deprecated Dec 2024)
    authUrl: 'https://www.facebook.com/v19.0/dialog/oauth',
    tokenUrl: 'https://graph.facebook.com/v19.0/oauth/access_token',
    profileUrl: 'https://graph.facebook.com/v19.0/me/accounts?fields=instagram_business_account{id,username}',
    scopes: 'instagram_basic,instagram_content_publish,pages_show_list,pages_read_engagement',
    clientId: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    extractProfile: (data) => {
      const page = (data.data || []).find(p => p.instagram_business_account);
      const ig = page?.instagram_business_account;
      return {
        id: ig?.id || 'unknown',
        username: ig?.username || 'Instagram Business Account'
      };
    }
  },
  snapchat: {
    authUrl: 'https://accounts.snapchat.com/accounts/oauth2/auth',
    tokenUrl: 'https://accounts.snapchat.com/accounts/oauth2/token',
    profileUrl: null,
    scopes: 'https://auth.snapchat.com/oauth2/api/user.display_name https://auth.snapchat.com/oauth2/api/user.external_id',
    clientId: process.env.SNAPCHAT_CLIENT_ID,
    clientSecret: process.env.SNAPCHAT_CLIENT_SECRET,
    defaultUsername: 'Snapchat User',
    pkce: true,
    extractProfile: () => ({
      id: null,
      username: 'Snapchat User'
    })
  },
  reddit: {
    authUrl: 'https://www.reddit.com/api/v1/authorize',
    tokenUrl: 'https://www.reddit.com/api/v1/access_token',
    profileUrl: 'https://oauth.reddit.com/api/v1/me',
    scopes: 'identity submit',
    clientId: process.env.REDDIT_CLIENT_ID,
    clientSecret: process.env.REDDIT_CLIENT_SECRET,
    extractProfile: (data) => ({
      id: data.id || 'unknown',
      username: data.name || 'Reddit User'
    }),
    useBasicAuthForToken: true
  },
  tiktok: {
    authUrl: 'https://www.tiktok.com/v2/auth/authorize/',
    tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/',
    profileUrl: 'https://open.tiktokapis.com/v2/user/info/',
    scopes: 'user.info.basic,video.upload',
    clientId: process.env.TIKTOK_CLIENT_KEY,
    clientSecret: process.env.TIKTOK_CLIENT_SECRET,
    clientIdParam: 'client_key',
    tokenClientIdParam: 'client_key',
    extractProfile: (data) => ({
      id: data.data?.user?.union_id || 'unknown',
      username: data.data?.user?.display_name || 'TikTok User'
    })
  },
  pinterest: {
    authUrl: 'https://www.pinterest.com/oauth/',
    tokenUrl: 'https://api.pinterest.com/v5/oauth/token',
    profileUrl: 'https://api.pinterest.com/v5/user_account',
    scopes: 'user_accounts:read,pins:write,boards:read',
    clientId: process.env.PINTEREST_CLIENT_ID || process.env.PINTEREST_APP_ID,
    clientSecret: process.env.PINTEREST_CLIENT_SECRET || process.env.PINTEREST_APP_SECRET,
    extractProfile: (data) => ({
      id: data.username || 'unknown',
      username: data.username || 'Pinterest User'
    }),
    useBasicAuthForToken: true
  },
  twitch: {
    authUrl: 'https://id.twitch.tv/oauth2/authorize',
    tokenUrl: 'https://id.twitch.tv/oauth2/token',
    profileUrl: 'https://api.twitch.tv/helix/users',
    scopes: 'user:read:email user:edit',
    clientId: process.env.TWITCH_CLIENT_ID,
    clientSecret: process.env.TWITCH_CLIENT_SECRET,
    extractProfile: (data) => ({
      id: data.data?.[0]?.id || 'unknown',
      username: data.data?.[0]?.display_name || 'Twitch User'
    })
  },
  threads: {
    authUrl: 'https://threads.net/oauth/authorize',
    tokenUrl: 'https://graph.threads.net/oauth/access_token',
    profileUrl: 'https://graph.threads.net/v1.0/me?fields=id,username',
    scopes: 'threads_basic,threads_content_publish',
    clientId: process.env.THREADS_APP_ID,
    clientSecret: process.env.THREADS_APP_SECRET,
    extractProfile: (data) => ({
      id: data.id || 'unknown',
      username: data.username || 'Threads User'
    })
  }
};

/* ── GET /:platform/callback — Handle OAuth callback ── */
router.get('/:platform/callback', async (req, res) => {
  const { platform } = req.params;
  const provider = OAUTH_PROVIDERS[platform];

  if (!provider) {
    return res.status(400).send('Unsupported platform');
  }

  try {
    const { userId, returnTo } = await verifyOAuthState(req.query.state, platform);

    // Re-verify the userId encoded in the state JWT exists and is active.
    // Prevents IDOR: an attacker with a captured state token cannot write OAuth
    // credentials to an arbitrary user account.
    const { data: stateUser, error: stateUserErr } = await supabase
      .from('users').select('id, is_active').eq('id', userId).single();
    if (stateUserErr || !stateUser || !stateUser.is_active) {
      logger.warn('OAuth callback rejected: state userId not found or inactive', { userId, platform });
      return res.redirect(`${getSafeReturnTo()}?platform_error=${platform}_invalid_state`);
    }

    if (req.query.error) {
      logger.error(`${platform} OAuth error`, { error: req.query.error });
      const errorUrl = new URL(returnTo || getSafeReturnTo());
      errorUrl.searchParams.set('platform_error', `${platform}_access_denied`);
      return res.redirect(errorUrl.toString());
    }

    const tokenParams = new URLSearchParams({
      [getTokenClientIdParam(provider)]: provider.clientId,
      client_secret: provider.clientSecret,
      code: req.query.code,
      redirect_uri: `${process.env.APP_URL || 'http://localhost:4000'}/api/v1/platforms/${platform}/callback`,
      grant_type: 'authorization_code'
    });

    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    if (provider.useBasicAuthForToken) {
      headers['Authorization'] = 'Basic ' + Buffer.from(`${provider.clientId}:${provider.clientSecret}`).toString('base64');
      tokenParams.delete(getTokenClientIdParam(provider));
      tokenParams.delete('client_secret');
    }

    const pkceVerifier = req.cookies?.[`oauth_pkce_${platform}`];
    if (pkceVerifier) {
      tokenParams.append('code_verifier', pkceVerifier);
      res.clearCookie(`oauth_pkce_${platform}`, { path: `/api/v1/platforms/${platform}` });
    }

    // Exchange code for tokens
    const tokenRes = await fetch(provider.tokenUrl, {
      method: 'POST',
      headers,
      body: tokenParams
    });

    const tokenData = await tokenRes.json();
    if (tokenData.error) throw new Error(tokenData.error_description || tokenData.error);

    const accessToken = tokenData.access_token;

    // Get Channel Info
    const profileHeaders = { 'Authorization': `Bearer ${accessToken}` };
    if (platform === 'twitch') {
      profileHeaders['Client-Id'] = provider.clientId;
    }

    let profile = {
      id: null,
      username: provider.defaultUsername || `${platform} User`,
    };

    if (provider.profileUrl) {
      const channelRes = await fetch(provider.profileUrl, { headers: profileHeaders });
      const channelData = await channelRes.json();
      if (channelRes.ok === false) throw new Error(channelData?.error?.message || `Profile lookup failed for ${platform}`);
      if (channelData.error) throw new Error(channelData.error.message || JSON.stringify(channelData.error));
      profile = provider.extractProfile(channelData);
    }

    const scopes = typeof tokenData.scope === 'string'
      ? tokenData.scope.split(/\s+/).filter(Boolean)
      : [];
    const expiresAt = tokenData.expires_in ? new Date(Date.now() + tokenData.expires_in * 1000) : null;

    // Upsert platform connection
    const connection = {
      user_id:           userId,
      platform:          platform,
      platform_user_id:  profile.id,
      platform_username: profile.username,
      access_token_enc:  encrypt(accessToken),
      token_expires_at:  expiresAt,
      scopes,
      is_active:         true,
      connected_at:      new Date(),
    };

    if (tokenData.refresh_token) {
      connection.refresh_token_enc = encrypt(tokenData.refresh_token);
    }

    await supabase.from('platform_connections').upsert(connection, { onConflict: 'user_id,platform' });

    logger.info(`${platform} connected successfully via OAuth`, { userId });
    const successUrl = new URL(returnTo || getSafeReturnTo());
    successUrl.searchParams.set('platform_success', platform);
    res.redirect(successUrl.toString());
  } catch (err) {
    logger.error(`${platform} callback error`, { err: err.message });
    const errorUrl = new URL(getSafeReturnTo());
    errorUrl.searchParams.set('platform_error', `${platform}_callback_failed`);
    res.redirect(errorUrl.toString());
  }
});

// Authenticated routes below
router.use(verifyToken);

/* ── POST /platforms/bluesky/connect — App Password flow ── */
router.post('/bluesky/connect', validateBody('blueskyConnect'), async (req, res) => {
  const { handle, appPassword } = req.body;

  try {
    const sessionRes = await fetch('https://bsky.social/xrpc/com.atproto.server.createSession', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: handle, password: appPassword }),
    });
    const session = await sessionRes.json();

    if (session.error) {
      logger.warn('Bluesky createSession failed', { handle, error: session.error });
      return res.status(401).json({ error: session.message || 'Invalid Bluesky handle or app password' });
    }

    const { accessJwt, refreshJwt, did } = session;
    const resolvedHandle = session.handle || handle;

    const db = getDb(req);
    const { data: connection, error } = await db.from('platform_connections').upsert({
      user_id:           req.user.id,
      platform:          'bluesky',
      platform_user_id:  did,
      platform_username: resolvedHandle,
      access_token_enc:  encrypt(accessJwt),
      refresh_token_enc: encrypt(refreshJwt),
      token_expires_at:  null,
      scopes:            ['atproto'],
      is_active:         true,
      connected_at:      new Date(),
    }, { onConflict: 'user_id,platform' }).select('id, platform, platform_username').single();

    if (error) {
      logger.error('Bluesky connection save failed', { err: error.message, userId: req.user.id });
      return res.status(500).json({ error: 'Failed to save Bluesky connection' });
    }

    logger.info('Bluesky connected via App Password', { userId: req.user.id, handle: resolvedHandle });
    res.status(201).json({ connection });
  } catch (err) {
    logger.error('Bluesky connect error', { err: err.message });
    res.status(500).json({ error: 'Failed to connect Bluesky account' });
  }
});

/* ── GET /platforms — list connected platforms ── */
router.get('/', async (req, res) => {
  const db = getDb(req);
  const { data, error } = await db.from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Failed to fetch platforms' });
  res.json({ platforms: data });
});

/* ── GET /platforms/:platform/auth — Initiate OAuth ── */
router.get('/:platform/auth', async (req, res) => {
  const { platform } = req.params;
  const provider = OAUTH_PROVIDERS[platform];

  if (!provider) {
    return res.status(400).json({ error: 'OAuth not supported or misconfigured for this platform.' });
  }

  if (!provider.clientId || !provider.clientSecret) {
    return res.status(500).json({ error: `Missing credentials for ${platform}. Please check .env.` });
  }

  try {
    const returnTo = getSafeReturnTo(req.query.returnTo);
    const { state } = await generateOAuthState(platform, req.user.id, returnTo);
    
    const oauthUrl = new URL(provider.authUrl);
    oauthUrl.searchParams.append(getClientIdParam(provider), provider.clientId);
    oauthUrl.searchParams.append('redirect_uri', `${process.env.APP_URL || 'http://localhost:4000'}/api/v1/platforms/${platform}/callback`);
    oauthUrl.searchParams.append('response_type', 'code');
    oauthUrl.searchParams.append('scope', provider.scopes);
    oauthUrl.searchParams.append('state', state);

    if (platform === 'youtube') {
      oauthUrl.searchParams.append('access_type', 'offline');
      oauthUrl.searchParams.append('prompt', 'consent');
      oauthUrl.searchParams.append('include_granted_scopes', 'true');
    }

    if (platform === 'reddit') {
      oauthUrl.searchParams.append('duration', 'permanent');
    }

    if (provider.pkce) {
      const { verifier, challenge } = generatePkcePair();
      oauthUrl.searchParams.append('code_challenge', challenge);
      oauthUrl.searchParams.append('code_challenge_method', 'S256');
      res.cookie(`oauth_pkce_${platform}`, verifier, {
        httpOnly: true,
        secure: isProd,
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000,
        path: `/api/v1/platforms/${platform}`,
      });
    }

    res.json({ url: oauthUrl.toString() });
  } catch (err) {
    logger.error(`Failed to generate ${platform} auth URL`, { err: err.message });
    res.status(500).json({ error: 'Failed to generate auth URL' });
  }
});

/* ── POST /platforms/connect — store OAuth tokens ── */
router.post('/connect', validateBody('platformConnection'), async (req, res) => {
  const { platform, accessToken, refreshToken, platformUserId, platformUsername, expiresAt } = req.body;
  const db = getDb(req);

  const { data, error } = await db.from('platform_connections').upsert({
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
  const db = getDb(req);
  const { data: connection, error } = await db.from('platform_connections')
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

  const db = getDb(req);
  const { data: connection, error } = await db.from('platform_connections')
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
  const db = getDb(req);
  const { error } = await db.from('platform_connections')
    .update({ is_active: false }).eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(404).json({ error: 'Connection not found' });
  res.status(204).send();
});

module.exports = router;
