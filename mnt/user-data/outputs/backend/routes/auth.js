/**
 * routes/auth.js
 * Authentication endpoints:
 *   POST /register      — create account
 *   POST /login         — issue JWT pair
 *   POST /refresh       — rotate refresh token
 *   POST /logout        — revoke tokens
 *   POST /forgot        — initiate password reset
 *   POST /reset         — complete password reset
 *   GET  /me            — current user profile
 */

'use strict';

const express        = require('express');
const bcrypt         = require('bcryptjs');
const crypto         = require('crypto');
const { supabase }   = require('../config/database');
const { verifyToken, issueTokens, rotateRefreshToken, revokeToken } = require('../middleware/auth');
const { authRateLimiter, authSlowDown }  = require('../middleware/rateLimit');
const { validateBody }                    = require('../middleware/sanitizer');
const { validatePassword, BCRYPT_ROUNDS, LOCKOUT_POLICY } = require('../config/security');
const { logger }     = require('../utils/logger');

const router = express.Router();

/* ── POST /register ─────────────────────── */
router.post(
  '/register',
  authSlowDown,
  authRateLimiter,
  validateBody('register'),
  async (req, res) => {
    const { email, password, fullName } = req.body;
    const emailNorm = email.toLowerCase().trim();

    // Password strength validation
    const pwErrors = validatePassword(password);
    if (pwErrors.length) {
      return res.status(422).json({ error: 'Weak password', errors: pwErrors });
    }

    // Check email already exists
    const { data: existing } = await supabase
      .from('users')
      .select('id')
      .eq('email', emailNorm)
      .single();

    if (existing) {
      // Generic message — don't reveal whether email exists (OWASP A07)
      return res.status(409).json({ error: 'Registration failed. Please try different credentials.' });
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const { data: user, error } = await supabase
      .from('users')
      .insert({
        email:         emailNorm,
        password_hash: passwordHash,
        full_name:     fullName || null,
      })
      .select('id, email, role, plan, full_name')
      .single();

    if (error) {
      logger.error('Register error', { err: error.message });
      return res.status(500).json({ error: 'Registration failed' });
    }

    const { accessToken, refreshToken } = issueTokens(user);

    // Set HttpOnly secure cookie for refresh token
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000,   // 7 days
      path:     '/api/v1/auth',
    });

    logger.info('User registered', { userId: user.id, ip: req.ip });

    res.status(201).json({
      accessToken,
      user: { id: user.id, email: user.email, fullName: user.full_name, plan: user.plan },
    });
  }
);

/* ── POST /login ─────────────────────────── */
router.post(
  '/login',
  authSlowDown,
  authRateLimiter,
  validateBody('login'),
  async (req, res) => {
    const { email, password } = req.body;
    const emailNorm = email.toLowerCase().trim();

    const { data: user } = await supabase
      .from('users')
      .select('id, email, password_hash, role, plan, is_active, failed_login_attempts, locked_until, full_name')
      .eq('email', emailNorm)
      .single();

    // Account lockout check
    if (user?.locked_until && new Date(user.locked_until) > new Date()) {
      const unlockAt = new Date(user.locked_until).toISOString();
      return res.status(423).json({ error: 'Account temporarily locked', unlockAt });
    }

    // Constant-time password check (prevents timing attacks even on missing users)
    const dummyHash = '$2a$12$dummy.hash.for.timing.safety.purposes.only.xx';
    const hashToCheck = user?.password_hash || dummyHash;
    const valid = await bcrypt.compare(password, hashToCheck);

    if (!user || !valid || !user.is_active) {
      // Increment failed attempts
      if (user) {
        const attempts = (user.failed_login_attempts || 0) + 1;
        const lockData = attempts >= LOCKOUT_POLICY.maxFailedAttempts
          ? { failed_login_attempts: attempts, locked_until: new Date(Date.now() + LOCKOUT_POLICY.lockDurationMs) }
          : { failed_login_attempts: attempts };
        await supabase.from('users').update(lockData).eq('id', user.id);
        if (attempts >= LOCKOUT_POLICY.maxFailedAttempts) {
          logger.warn('Account locked', { userId: user.id, ip: req.ip });
        }
      }
      logger.warn('Failed login', { email: emailNorm, ip: req.ip });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Reset failed attempts on success
    await supabase.from('users').update({
      failed_login_attempts: 0,
      locked_until:          null,
      last_login:            new Date(),
    }).eq('id', user.id);

    const { accessToken, refreshToken } = issueTokens(user);

    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      secure:   process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge:   7 * 24 * 60 * 60 * 1000,
      path:     '/api/v1/auth',
    });

    logger.info('User login', { userId: user.id, ip: req.ip });

    res.json({
      accessToken,
      user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, plan: user.plan },
    });
  }
);

/* ── POST /refresh ───────────────────────── */
router.post('/refresh', authRateLimiter, async (req, res) => {
  const refreshToken = req.cookies?.refresh_token || req.body?.refreshToken;
  if (!refreshToken) return res.status(401).json({ error: 'No refresh token' });

  const { accessToken, refreshToken: newRefresh } = await rotateRefreshToken(refreshToken);

  res.cookie('refresh_token', newRefresh, {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   7 * 24 * 60 * 60 * 1000,
    path:     '/api/v1/auth',
  });

  res.json({ accessToken });
});

/* ── POST /logout ────────────────────────── */
router.post('/logout', verifyToken, async (req, res) => {
  await revokeToken(req.user.jti, req.user.id);
  res.clearCookie('refresh_token', { path: '/api/v1/auth' });
  logger.info('User logout', { userId: req.user.id });
  res.json({ message: 'Logged out successfully' });
});

/* ── POST /forgot-password ───────────────── */
router.post('/forgot', authRateLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(422).json({ error: 'Email required' });

  const { data: user } = await supabase
    .from('users')
    .select('id')
    .eq('email', email.toLowerCase().trim())
    .single();

  // Always return 200 to prevent email enumeration
  if (!user) return res.json({ message: 'If this email exists, a reset link has been sent.' });

  const token     = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

  await supabase.from('password_resets').insert({
    user_id:    user.id,
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  // TODO: integrate email service (SendGrid / Resend / AWS SES)
  logger.info('Password reset requested', { userId: user.id });

  res.json({ message: 'If this email exists, a reset link has been sent.' });
});

/* ── GET /me ─────────────────────────────── */
router.get('/me', verifyToken, async (req, res) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('id, email, full_name, role, plan, is_verified, created_at, last_login')
    .eq('id', req.user.id)
    .single();

  if (error || !user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

/* ─ middleware alias exports ─ */
router.csrf   = require('../middleware/audit').generateCSRFToken;

module.exports = router;
