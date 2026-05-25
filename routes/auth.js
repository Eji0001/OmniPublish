/**
 * routes/auth.js — Register, login, refresh, logout + magic link, OAuth exchange, GDPR
 * Covers: OWASP A07 (Authentication Failures)
 */

'use strict';

const express         = require('express');
const bcrypt          = require('bcryptjs');
const crypto          = require('crypto');
const jwt             = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { supabase }    = require('../config/database');
const { issueTokens, rotateRefreshToken, revokeToken, verifyToken, recordSession, revokeUserSessions } = require('../middleware/auth');
const { validateBody }   = require('../middleware/sanitizer');
const { authRateLimiter, authSlowDown, resetPasswordRateLimiter } = require('../middleware/rateLimit');
const { generateCSRFToken } = require('../middleware/csrf');
const { BCRYPT_ROUNDS, LOCKOUT_POLICY, validatePassword, JWT_CONFIG } = require('../config/security');
const { mirrorAuthUser } = require('../utils/authMirror');
const { logger }      = require('../utils/logger');

const router = express.Router();

const isProd = process.env.NODE_ENV === 'production';
const normalizeEmail = (value) => String(value || '').trim().toLowerCase();
const isLocalDevHost = (host) => /^(localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i.test(String(host || '').trim());
const isDemoMode = (req) => process.env.OMNIPUBLISH_DEMO_MODE === 'true' || isLocalDevHost(req?.hostname || req?.headers?.host);
const TOKEN_PURPOSE = {
  OAUTH_EXCHANGE: 'oauth_exchange',
};
const DEMO_USER_EMAIL = normalizeEmail(process.env.OMNIPUBLISH_DEMO_EMAIL || 'demo@omnipublish.local');
const DEMO_USER_NAME = process.env.OMNIPUBLISH_DEMO_NAME || 'Demo User';
const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');
const getDb = (req) => req.db || supabase;

const buildAuthResponse = ({ user, tokens, csrfToken }) => ({
  user: { id: user.id, email: user.email, role: user.role, plan: user.plan },
  accessToken: tokens.accessToken,
  csrfToken,
});

const issueSessionTokens = async (user) => {
  const tokens = issueTokens(user);
  await recordSession(user.id, tokens.jti);
  return tokens;
};

const getDemoUser = async () => {
  const demoProfile = {
    email: DEMO_USER_EMAIL,
    full_name: DEMO_USER_NAME,
    role: 'user',
    plan: 'pro',
    user_type: 'creator',
    is_active: true,
    is_verified: true,
    onboarding_completed_at: new Date(),
    last_login_at: new Date(),
  };

  const { data: existing, error: lookupError } = await supabase.from('users')
    .select('id, email, full_name, role, plan, user_type, onboarding_completed_at, is_active, is_verified')
    .ilike('email', DEMO_USER_EMAIL)
    .limit(1)
    .single();

  if (lookupError && lookupError.code !== 'PGRST116') {
    throw Object.assign(new Error('Failed to load demo user'), { status: 500 });
  }

  if (existing?.id) {
    const { data: updated, error: updateError } = await supabase.from('users')
      .update(demoProfile)
      .eq('id', existing.id)
      .select('id, email, full_name, role, plan, user_type, onboarding_completed_at, is_active, is_verified')
      .single();

    if (updateError || !updated) {
      throw Object.assign(new Error('Failed to bootstrap demo session'), { status: 500 });
    }

    return updated;
  }

  const { data: created, error: createError } = await supabase.from('users')
    .insert({ id: uuidv4(), ...demoProfile, password_hash: null })
    .select('id, email, full_name, role, plan, user_type, onboarding_completed_at, is_active, is_verified')
    .single();

  if (createError || !created) {
    throw Object.assign(new Error('Failed to bootstrap demo session'), { status: 500 });
  }

  return created;
};

// Set httpOnly refresh cookie alongside every response that issues tokens
const setRefreshCookie = (res, refreshToken) => {
  res.cookie('omni_refresh', refreshToken, {
    httpOnly: true, secure: isProd, sameSite: 'Strict',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
};

/* ── POST /auth/register ── */
router.post('/register', authSlowDown, authRateLimiter, validateBody('register'), async (req, res) => {
  const { email, password, fullName } = req.body;
  const normalizedEmail = normalizeEmail(email);

  const pwErrors = validatePassword(password);
  if (pwErrors.length) return res.status(422).json({ error: 'Weak password', errors: pwErrors });

  const { data: existing, error: existingError } = await supabase.from('users')
    .select('id, email, full_name, is_verified, password_hash, role, plan')
    .ilike('email', normalizedEmail)
    .order('locked_until', { ascending: true, nullsFirst: true })
    .order('failed_login_attempts', { ascending: true })
    .limit(1)
    .single();

  if (existingError && existingError.code !== 'PGRST116') {
    logger.error('Register lookup failed', { err: existingError.message });
    return res.status(500).json({ error: 'Registration failed' });
  }

  if (existing?.is_verified) return res.status(409).json({ error: 'Email already registered' });

  let user = existing;
  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const sessionUser = { is_verified: true };

  if (user) {
    const { data: updated, error } = await supabase.from('users')
      .update({
        password_hash: passwordHash,
        full_name: fullName || user.full_name || null,
        is_active: true,
        is_verified: true,
        failed_login_attempts: 0,
        locked_until: null,
        last_login_at: new Date(),
      })
      .eq('id', user.id)
      .select('id, email, full_name, is_verified, role, plan')
      .single();
    if (error) { logger.error('Register update failed', { err: error.message }); return res.status(500).json({ error: 'Registration failed' }); }
    user = updated;
  } else {
    const { data: created, error } = await supabase.from('users')
      .insert({
        id: uuidv4(),
        email: normalizedEmail,
        password_hash: passwordHash,
        full_name: fullName || null,
        role: 'user',
        plan: 'free',
        is_active: true,
        is_verified: true,
        last_login_at: new Date(),
      })
      .select('id, email, full_name, is_verified, role, plan')
      .single();
    if (error) { logger.error('Register failed', { err: error.message }); return res.status(500).json({ error: 'Registration failed' }); }
    user = created;
  }

  const tokens = await issueSessionTokens({ ...user, ...sessionUser });
  await mirrorAuthUser({ email: normalizedEmail, password, fullName, source: 'register' });
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  setRefreshCookie(res, tokens.refreshToken);
  logger.info('User registered', { userId: user.id });
  res.json(buildAuthResponse({ user: { ...user, ...sessionUser }, tokens, csrfToken }));
});

/* ── POST /auth/dev-session ──
   Allowed only for localhost requests or when OMNIPUBLISH_DEMO_MODE=true.
   isDemoMode(req) enforces this per-request regardless of NODE_ENV,
   so production requests (non-localhost hostnames) always get 404. */
router.post('/dev-session', authSlowDown, authRateLimiter, async (req, res) => {
  if (!isDemoMode(req)) return res.status(404).json({ error: 'Not found' });

  try {
    const user = await getDemoUser();
    const tokens = await issueSessionTokens(user);
    const csrfToken = generateCSRFToken();
    res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
    setRefreshCookie(res, tokens.refreshToken);
    logger.info('Demo session bootstrapped', { userId: user.id });
    res.json(buildAuthResponse({ user, tokens, csrfToken }));
  } catch (err) {
    logger.error('Demo session bootstrap failed', { err: err.message });
    res.status(err.status || 500).json({ error: 'Failed to start demo session' });
  }
});

/* ── POST /auth/login ── */
router.post('/login', authSlowDown, authRateLimiter, validateBody('login'), async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = normalizeEmail(email);

  const { data: user, error: loginLookupErr } = await supabase.from('users')
    .select('id, email, password_hash, role, plan, is_active, is_verified, failed_login_attempts, locked_until')
    .ilike('email', normalizedEmail)
    .order('locked_until', { ascending: true, nullsFirst: true })
    .order('failed_login_attempts', { ascending: true })
    .limit(1)
    .single();

  if (loginLookupErr && loginLookupErr.code !== 'PGRST116') {
    logger.error('Login DB lookup failed', { err: loginLookupErr.message });
    return res.status(500).json({ error: 'Login failed. Please try again.' });
  }
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });
  if (!user.is_verified) return res.status(403).json({ error: 'Verify your email to continue.' });
  if (!user.password_hash) return res.status(401).json({ error: 'Password login is not available for this account' });
  if (user.locked_until && new Date(user.locked_until) > new Date())
    return res.status(429).json({ error: 'Account temporarily locked', retryAfter: user.locked_until });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    const newAttempts = (user.failed_login_attempts || 0) + 1;
    // Exponential backoff: 15m, 22.5m, 33.75m, up to 24h
    const exponentialBackoff = (attempts) => {
      const baseMs = LOCKOUT_POLICY.lockDurationMs;
      const delayMs = Math.min(baseMs * Math.pow(1.5, Math.max(0, attempts - 5)), 86400000);
      return delayMs;
    };
    const lockUpdate = {
      failed_login_attempts: newAttempts,
      ...(newAttempts >= LOCKOUT_POLICY.maxFailedAttempts ? { locked_until: new Date(Date.now() + exponentialBackoff(newAttempts)) } : {}),
    };
    // Optimistic concurrency: only update if the counter we read is still current
    await supabase.from('users').update(lockUpdate)
      .eq('id', user.id)
      .eq('failed_login_attempts', user.failed_login_attempts || 0);
    logger.warn('Failed login attempt', { userId: user.id, attempts: newAttempts, ip: req.ip });
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  await supabase.from('users').update({ failed_login_attempts: 0, last_login_at: new Date() }).eq('id', user.id);

  const tokens    = await issueSessionTokens(user);
  await mirrorAuthUser({ email: normalizedEmail, password, fullName: user.full_name || null, source: 'login' });
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  setRefreshCookie(res, tokens.refreshToken);
  logger.info('User logged in', { userId: user.id });
  res.json(buildAuthResponse({ user, tokens, csrfToken }));
});

/* ── POST /auth/refresh ── */
router.post('/refresh', authRateLimiter, async (req, res) => {
  const refreshToken = req.cookies?.omni_refresh;
  if (!refreshToken) return res.status(422).json({ error: 'refreshToken required' });
  try {
    const tokens    = await rotateRefreshToken(refreshToken);
    await recordSession(tokens.userId, tokens.jti);
    const csrfToken = generateCSRFToken();
    res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
    setRefreshCookie(res, tokens.refreshToken);
    res.json({ accessToken: tokens.accessToken, csrfToken });
  } catch (err) {
    res.clearCookie('omni_refresh');
    res.status(err.status || 401).json({ error: err.message });
  }
});

/* ── POST /auth/logout ── */
router.post('/logout', verifyToken, async (req, res) => {
  await revokeToken(req.user.jti, req.user.id);
  res.clearCookie('csrf_token');
  res.clearCookie('omni_refresh', { httpOnly: true, secure: isProd, sameSite: 'Strict' });
  logger.info('User logged out', { userId: req.user.id });
  res.json({ message: 'Logged out successfully' });
});

/* ── GET /auth/me ── */
router.get('/me', verifyToken, async (req, res) => {
  const db = getDb(req);
  const { data: user } = await db.from('users')
    .select('id, email, full_name, role, plan, user_type, onboarding_completed_at, created_at, last_login_at')
    .eq('id', req.user.id).single();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

/* ── PATCH /auth/me/profile ── */
router.patch('/me/profile', verifyToken, validateBody('userProfile'), async (req, res) => {
  const { userType, onboardingCompleted } = req.body;
  const update = {};
  if (userType !== undefined) update.user_type = userType;
  if (onboardingCompleted !== undefined) update.onboarding_completed_at = onboardingCompleted ? new Date() : null;
  if (!Object.keys(update).length) return res.status(422).json({ error: 'Nothing to update' });

  const db = getDb(req);
  const { data: user, error } = await db.from('users')
    .update(update)
    .eq('id', req.user.id)
    .select('id, email, role, plan, user_type, onboarding_completed_at')
    .single();
  if (error) return res.status(500).json({ error: 'Profile update failed' });
  logger.info('Profile updated', { userId: req.user.id, fields: Object.keys(update) });
  res.json({ user });
});

/* ── GET /auth/export-data (GDPR Art. 20) ── */
router.get('/export-data', verifyToken, async (req, res) => {
  const uid = req.user.id;
  const db = getDb(req);
  const [{ data: user }, { count: postCount }, { data: connections }, { data: mediaFiles }, { count: auditCount }] = await Promise.all([
    db.from('users').select('id, email, full_name, role, plan, user_type, created_at, last_login_at').eq('id', uid).single(),
    db.from('posts').select('*', { count: 'exact', head: true }).eq('user_id', uid),
    db.from('platform_connections').select('platform, platform_username, is_active, connected_at').eq('user_id', uid),
    db.from('media_files').select('filename, original_name, mime_type, size_bytes, cdn_url, created_at').eq('user_id', uid),
    db.from('audit_logs').select('*', { count: 'exact', head: true }).eq('user_id', uid),
  ]);
  res.json({ exportedAt: new Date(), user, postCount: postCount || 0, connections, mediaFiles, auditLogCount: auditCount || 0 });
});

/* ── DELETE /auth/me (GDPR Art. 17) ── */
router.delete('/me', verifyToken, async (req, res) => {
  const { password } = req.body;
  const db = getDb(req);

  const { data: user } = await db.from('users')
    .select('id, password_hash').eq('id', req.user.id).eq('is_active', true).single();
  if (!user) return res.status(404).json({ error: 'User not found' });

  if (user.password_hash) {
    if (!password) return res.status(422).json({ error: 'password required to confirm account deletion' });
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Incorrect password' });
  }

  await revokeUserSessions(user.id, req.user.jti);

  const [userUpdate, connectionsUpdate] = await Promise.all([
    db.from('users').update({
      is_active: false,
      email: `deleted_${user.id}@deleted.local`,
      password_hash: null,
      full_name: null,
    }).eq('id', user.id),
    db.from('platform_connections').update({ is_active: false }).eq('user_id', user.id),
  ]);
  if (userUpdate.error || connectionsUpdate.error) {
    logger.error('Account deletion failed', {
      userId: user.id,
      userError: userUpdate.error?.message,
      connectionError: connectionsUpdate.error?.message,
    });
    return res.status(500).json({ error: 'Account deletion failed' });
  }

  res.clearCookie('csrf_token');
  res.clearCookie('omni_refresh', { httpOnly: true, secure: isProd, sameSite: 'Strict' });
  logger.info('Account deleted', { userId: user.id });
  res.json({ message: 'Account deleted. Your data has been anonymised.' });
});

/* ── POST /auth/forgot-password ── */
router.post('/forgot-password', authRateLimiter, validateBody('forgotPassword'), async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);
  const requestStart = Date.now();
  const MIN_RESPONSE_MS = 200;
  const delayResponse = async () => {
    const elapsed = Date.now() - requestStart;
    if (elapsed < MIN_RESPONSE_MS) await new Promise(r => setTimeout(r, MIN_RESPONSE_MS - elapsed));
  };

  const { data: user, error: fpLookupErr } = await supabase.from('users').select('id').ilike('email', normalizedEmail).eq('is_active', true).limit(1).single();
  if (fpLookupErr && fpLookupErr.code !== 'PGRST116') {
    logger.error('Forgot-password DB lookup failed', { err: fpLookupErr.message });
    await delayResponse();
    return res.status(500).json({ error: 'Request failed. Please try again.' });
  }
  if (!user) {
    await delayResponse();
    return res.json({ message: 'If that email is registered you will receive a reset link shortly' });
  }

  await supabase.from('password_resets').delete()
    .eq('user_id', user.id)
    .eq('purpose', 'password_reset')
    .is('used_at', null);

  const plainToken = `pr_${crypto.randomBytes(32).toString('hex')}`;
  const tokenHash  = crypto.createHash('sha256').update(plainToken).digest('hex');
  const expiresAt  = new Date(Date.now() + 60 * 60 * 1000);

  await supabase.from('password_resets').insert({
    id: uuidv4(),
    user_id: user.id,
    token_hash: tokenHash,
    purpose: 'password_reset',
    expires_at: expiresAt,
  });

  if (!isProd) logger.info('Password reset token (dev only)', { userId: user.id, tokenHash });

  logger.info('Password reset requested', { userId: user.id });
  await delayResponse();
  res.json({ message: 'If that email is registered you will receive a reset link shortly' });
});

/* ── POST /auth/reset-password ── */
router.post('/reset-password', resetPasswordRateLimiter, validateBody('resetPassword'), async (req, res) => {
  const { token, password } = req.body;
  if (!token.startsWith('pr_')) return res.status(400).json({ error: 'Invalid or expired reset token' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const { data: record } = await supabase.from('password_resets')
    .select('id, user_id, expires_at, used_at').eq('token_hash', tokenHash).single();

  if (!record)                                   return res.status(400).json({ error: 'Invalid or expired reset token' });
  if (record.used_at)                            return res.status(400).json({ error: 'Reset token already used' });
  if (new Date(record.expires_at) < new Date())  return res.status(400).json({ error: 'Reset token has expired' });

  const pwErrors = validatePassword(password);
  if (pwErrors.length) return res.status(422).json({ error: 'Weak password', errors: pwErrors });

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  await supabase.from('users').update({ password_hash: passwordHash, failed_login_attempts: 0, locked_until: null }).eq('id', record.user_id);
  await supabase.from('password_resets').update({ used_at: new Date() }).eq('id', record.id);

  logger.info('Password reset completed', { userId: record.user_id });
  res.json({ message: 'Password updated successfully. Please log in with your new password.' });
});

/* ── POST /auth/magic-link ── */
router.post('/magic-link', authRateLimiter, validateBody('magicLink'), async (req, res) => {
  const { email } = req.body;
  const normalizedEmail = normalizeEmail(email);

  const { data: user, error: mlLookupErr } = await supabase.from('users')
    .select('id').ilike('email', normalizedEmail).eq('is_active', true).limit(1).single();

  if (mlLookupErr && mlLookupErr.code !== 'PGRST116') {
    logger.error('Magic-link DB lookup failed', { err: mlLookupErr.message });
    return res.status(500).json({ error: 'Request failed. Please try again.' });
  }
  if (!user) {
    logger.info('Magic link requested for unknown email (silently ignored)');
    return res.json({ message: 'If that email is registered you will receive a login link shortly' });
  }

  await supabase.from('password_resets').delete()
    .eq('user_id', user.id)
    .eq('purpose', 'magic_link')
    .is('used_at', null);

  const plainToken = `ml_${crypto.randomBytes(32).toString('hex')}`;
  const tokenHash  = crypto.createHash('sha256').update(plainToken).digest('hex');
  const expiresAt  = new Date(Date.now() + (parseInt(process.env.MAGIC_LINK_EXPIRY_MINS || '15', 10)) * 60 * 1000);

  await supabase.from('password_resets').insert({
    id: uuidv4(),
    user_id: user.id,
    token_hash: tokenHash,
    purpose: 'magic_link',
    expires_at: expiresAt,
  });

  const loginUrl = `${process.env.APP_URL || 'http://localhost:4000'}/?magic=${plainToken}`;
  if (!isProd) logger.info('Magic link (dev only)', { userId: user.id, loginUrl });

  logger.info('Magic link issued', { userId: user.id });
  res.json({ message: 'If that email is registered you will receive a login link shortly' });
});

/* ── POST /auth/magic-link/verify (changed from GET to prevent CSRF via img tags) ── */
router.post('/magic-link/verify', validateBody('magicLinkVerify'), async (req, res) => {
  const { token } = req.body;
  if (!token.startsWith('ml_')) return res.status(400).json({ error: 'Invalid or expired link' });
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

  const { data: record } = await supabase.from('password_resets')
    .select('id, user_id, expires_at, used_at').eq('token_hash', tokenHash).single();

  if (!record)                                   return res.status(400).json({ error: 'Invalid or expired link' });
  if (record.used_at)                            return res.status(400).json({ error: 'Link already used' });
  if (new Date(record.expires_at) < new Date())  return res.status(400).json({ error: 'Link has expired' });

  await supabase.from('password_resets').update({ used_at: new Date() }).eq('id', record.id);

  const { data: user } = await supabase.from('users')
    .select('id, email, role, plan, full_name, is_verified').eq('id', record.user_id).single();
  if (!user) return res.status(400).json({ error: 'User not found' });

  await supabase.from('users').update({ is_verified: true, failed_login_attempts: 0, locked_until: null, last_login_at: new Date() }).eq('id', user.id);
  await mirrorAuthUser({ email: user.email, fullName: user.full_name || null, source: 'magic_link' });

  const tokens    = await issueSessionTokens(user);
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  setRefreshCookie(res, tokens.refreshToken);
  logger.info('Magic link login', { userId: user.id });
  res.json(buildAuthResponse({ user, tokens, csrfToken }));
});

/* ── POST /auth/confirm-email ── */
router.post('/confirm-email', validateBody('confirmEmail'), async (req, res) => {
  const { token } = req.body;

  let payload;
  try {
    payload = jwt.verify(token, JWT_CONFIG.emailConfirmSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
    });
  } catch {
    return res.status(400).json({ error: 'Invalid or expired confirmation link' });
  }

  if (payload.purpose !== 'email_confirm' || !payload.userId) {
    return res.status(400).json({ error: 'Invalid confirmation link' });
  }

  const { data: user } = await supabase.from('users')
    .select('id, email, role, plan, full_name, is_verified')
    .eq('id', payload.userId)
    .single();
  if (!user) return res.status(400).json({ error: 'User not found' });

  await supabase.from('users').update({ is_verified: true, failed_login_attempts: 0, locked_until: null, last_login_at: new Date() }).eq('id', user.id);
  await mirrorAuthUser({ email: user.email, fullName: user.full_name || null, source: 'confirm_email' });

  const tokens    = await issueSessionTokens({ ...user, is_verified: true });
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  setRefreshCookie(res, tokens.refreshToken);
  logger.info('Email confirmed', { userId: user.id });
  res.json(buildAuthResponse({ user: { ...user, is_verified: true }, tokens, csrfToken }));
});

/* ── POST /auth/oauth/exchange — exchange one-time code for JWT (from Google OAuth redirect) ── */
router.post('/oauth/exchange', validateBody('oauthExchange'), async (req, res) => {
  const { code } = req.body;
  const tokenHash = hashToken(code);

  let payload;
  try {
    payload = jwt.verify(code, JWT_CONFIG.oauthExchangeSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer: JWT_CONFIG.issuer,
      audience: JWT_CONFIG.audience,
    });
  } catch {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  if (payload.purpose !== 'oauth_exchange' || !payload.userId) {
    return res.status(400).json({ error: 'Invalid code' });
  }

  const { data: exchangeRecord, error: exchangeError } = await supabase.from('password_resets')
    .update({ used_at: new Date() })
    .eq('token_hash', tokenHash)
    .eq('user_id', payload.userId)
    .eq('purpose', TOKEN_PURPOSE.OAUTH_EXCHANGE)
    .is('used_at', null)
    .gt('expires_at', new Date().toISOString())
    .select('id')
    .single();

  if (exchangeError || !exchangeRecord) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const { data: user } = await supabase.from('users')
    .select('id, email, role, plan, full_name, is_verified').eq('id', payload.userId).single();
  if (!user) return res.status(400).json({ error: 'User not found' });

  await supabase.from('users').update({ is_verified: true, failed_login_attempts: 0, locked_until: null, last_login_at: new Date() }).eq('id', user.id);
  await mirrorAuthUser({ email: user.email, fullName: user.full_name || null, source: 'oauth_exchange' });

  const tokens    = await issueSessionTokens(user);
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: isProd, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  setRefreshCookie(res, tokens.refreshToken);
  logger.info('OAuth exchange login', { userId: user.id });
  res.json(buildAuthResponse({ user, tokens, csrfToken }));
});

module.exports = router;
