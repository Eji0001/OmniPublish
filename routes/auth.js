/**
 * routes/auth.js — Register, login, refresh, logout
 * Covers: OWASP A07 (Authentication Failures)
 */

'use strict';

const express         = require('express');
const bcrypt          = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { supabase }    = require('../config/database');
const { issueTokens, rotateRefreshToken, revokeToken, verifyToken } = require('../middleware/auth');
const { validateBody }   = require('../middleware/sanitizer');
const { authRateLimiter, authSlowDown } = require('../middleware/rateLimit');
const { generateCSRFToken } = require('../middleware/csrf');
const { BCRYPT_ROUNDS, validatePassword } = require('../config/security');
const { logger }      = require('../utils/logger');

const router = express.Router();

/* ── POST /auth/register ── */
router.post('/register', authSlowDown, authRateLimiter, validateBody('register'), async (req, res) => {
  const { email, password, fullName } = req.body;

  const pwErrors = validatePassword(password);
  if (pwErrors.length) return res.status(422).json({ error: 'Weak password', errors: pwErrors });

  const { data: existing } = await supabase.from('users').select('id').eq('email', email).single();
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const { data: user, error } = await supabase.from('users')
    .insert({ id: uuidv4(), email, password_hash: passwordHash, full_name: fullName || null, role: 'user', plan: 'free', is_active: true })
    .select('id, email, role, plan')
    .single();

  if (error) { logger.error('Register failed', { err: error.message }); return res.status(500).json({ error: 'Registration failed' }); }

  const tokens    = issueTokens(user);
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: true, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  logger.info('User registered', { userId: user.id });
  res.status(201).json({ user: { id: user.id, email: user.email, role: user.role, plan: user.plan }, ...tokens, csrfToken });
});

/* ── POST /auth/login ── */
router.post('/login', authSlowDown, authRateLimiter, validateBody('login'), async (req, res) => {
  const { email, password } = req.body;

  const { data: user } = await supabase.from('users')
    .select('id, email, password_hash, role, plan, is_active, failed_login_attempts, locked_until')
    .eq('email', email).single();

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (!user.is_active) return res.status(403).json({ error: 'Account deactivated' });
  if (user.locked_until && new Date(user.locked_until) > new Date())
    return res.status(429).json({ error: 'Account temporarily locked', retryAfter: user.locked_until });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) {
    await supabase.from('users').update({ failed_login_attempts: (user.failed_login_attempts || 0) + 1 }).eq('id', user.id);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  await supabase.from('users').update({ failed_login_attempts: 0, last_login_at: new Date() }).eq('id', user.id);

  const tokens    = issueTokens(user);
  const csrfToken = generateCSRFToken();
  res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: true, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
  logger.info('User logged in', { userId: user.id });
  res.json({ user: { id: user.id, email: user.email, role: user.role, plan: user.plan }, ...tokens, csrfToken });
});

/* ── POST /auth/refresh ── */
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(422).json({ error: 'refreshToken required' });
  try {
    const tokens    = await rotateRefreshToken(refreshToken);
    const csrfToken = generateCSRFToken();
    res.cookie('csrf_token', csrfToken, { httpOnly: false, secure: true, sameSite: 'Strict', maxAge: 15 * 60 * 1000 });
    res.json({ ...tokens, csrfToken });
  } catch (err) {
    res.status(err.status || 401).json({ error: err.message });
  }
});

/* ── POST /auth/logout ── */
router.post('/logout', verifyToken, async (req, res) => {
  await revokeToken(req.user.jti, req.user.id);
  res.clearCookie('csrf_token');
  logger.info('User logged out', { userId: req.user.id });
  res.json({ message: 'Logged out successfully' });
});

/* ── GET /auth/me ── */
router.get('/me', verifyToken, async (req, res) => {
  const { data: user } = await supabase.from('users')
    .select('id, email, full_name, role, plan, created_at, last_login_at').eq('id', req.user.id).single();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

module.exports = router;
