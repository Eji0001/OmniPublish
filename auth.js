/**
 * middleware/auth.js
 * JWT bearer-token verification with:
 *   - RS256 / HS256 support
 *   - Token blacklisting via Supabase
 *   - Refresh token rotation
 *   - Role-based access control (RBAC)
 * Covers: OWASP A07 (Identification and Authentication Failures)
 */

'use strict';

const jwt             = require('jsonwebtoken');
const { supabase }    = require('../config/database');
const { JWT_CONFIG }  = require('../config/security');
const { logger }      = require('../utils/logger');

/* ── Token verification core ────────────── */

/**
 * verifyToken — validates JWT from Authorization header.
 * Checks: signature · expiry · issuer · audience · blacklist
 */
const verifyToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.slice(7);

  let payload;
  try {
    payload = jwt.verify(token, JWT_CONFIG.accessSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer:     JWT_CONFIG.issuer,
      audience:   JWT_CONFIG.audience,
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    logger.warn('Invalid JWT', { ip: req.ip, err: err.message });
    return res.status(401).json({ error: 'Invalid token' });
  }

  // Check token blacklist (revoked / logged-out tokens)
  const { data: revoked } = await supabase
    .from('revoked_tokens')
    .select('id')
    .eq('jti', payload.jti)
    .single();

  if (revoked) {
    logger.warn('Revoked token used', { userId: payload.sub, ip: req.ip });
    return res.status(401).json({ error: 'Token has been revoked' });
  }

  // Attach user context to request
  req.user = {
    id:    payload.sub,
    email: payload.email,
    role:  payload.role || 'user',
    plan:  payload.plan || 'free',
    jti:   payload.jti,
  };

  next();
};

/* ── Role-based access control ──────────── */

/**
 * requireRole — factory for role guards.
 * Usage: router.delete('/admin-route', requireRole('admin'), handler)
 */
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthenticated' });
  }
  if (!roles.includes(req.user.role)) {
    logger.warn('Unauthorised role access', {
      userId:   req.user.id,
      required: roles,
      actual:   req.user.role,
      path:     req.path,
    });
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

/* ── Plan-based feature guards ──────────── */

const PLAN_HIERARCHY = { free: 0, starter: 1, pro: 2, enterprise: 3 };

const requirePlan = (minPlan) => (req, res, next) => {
  const userPlanLevel = PLAN_HIERARCHY[req.user?.plan] ?? 0;
  const requiredLevel = PLAN_HIERARCHY[minPlan] ?? 0;
  if (userPlanLevel < requiredLevel) {
    return res.status(403).json({
      error:    'Plan upgrade required',
      required: minPlan,
      current:  req.user?.plan,
    });
  }
  next();
};

/* ── Token generation helpers ───────────── */

const { v4: uuidv4 } = require('uuid');

/**
 * issueTokens — creates access + refresh token pair.
 * @param {Object} user — { id, email, role, plan }
 */
const issueTokens = (user) => {
  const jti = uuidv4(); // unique token ID for blacklisting

  const accessToken = jwt.sign(
    { email: user.email, role: user.role, plan: user.plan, jti },
    JWT_CONFIG.accessSecret,
    {
      subject:   user.id,
      expiresIn: JWT_CONFIG.accessExpiresIn,
      issuer:    JWT_CONFIG.issuer,
      audience:  JWT_CONFIG.audience,
      algorithm: JWT_CONFIG.algorithm,
    }
  );

  const refreshToken = jwt.sign(
    { jti },
    JWT_CONFIG.refreshSecret,
    {
      subject:   user.id,
      expiresIn: JWT_CONFIG.refreshExpiresIn,
      issuer:    JWT_CONFIG.issuer,
      audience:  JWT_CONFIG.audience,
      algorithm: JWT_CONFIG.algorithm,
    }
  );

  return { accessToken, refreshToken, jti };
};

/**
 * rotateRefreshToken — validates old refresh token and issues new pair.
 * Old refresh token is blacklisted immediately (rotation).
 */
const rotateRefreshToken = async (oldRefreshToken) => {
  let payload;
  try {
    payload = jwt.verify(oldRefreshToken, JWT_CONFIG.refreshSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer:     JWT_CONFIG.issuer,
      audience:   JWT_CONFIG.audience,
    });
  } catch {
    throw Object.assign(new Error('Invalid refresh token'), { status: 401 });
  }

  // Blacklist old token
  await supabase.from('revoked_tokens').insert({ jti: payload.jti, user_id: payload.sub });

  // Fetch fresh user from DB (check account still active)
  const { data: user, error } = await supabase
    .from('users')
    .select('id, email, role, plan, is_active')
    .eq('id', payload.sub)
    .single();

  if (error || !user || !user.is_active) {
    throw Object.assign(new Error('Account not found or inactive'), { status: 401 });
  }

  return issueTokens(user);
};

/**
 * revokeToken — adds a JTI to the blacklist (logout).
 */
const revokeToken = async (jti, userId) => {
  await supabase.from('revoked_tokens').insert({ jti, user_id: userId });
};

module.exports = {
  verifyToken,
  requireRole,
  requirePlan,
  issueTokens,
  rotateRefreshToken,
  revokeToken,
};
