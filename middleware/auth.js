/**
 * middleware/auth.js
 * JWT bearer-token verification with RS256/HS256, token blacklisting, RBAC.
 * Covers: OWASP A07 (Identification and Authentication Failures)
 */

'use strict';

const jwt            = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const { supabase }   = require('../config/database');
const { JWT_CONFIG } = require('../config/security');
const { logger }     = require('../utils/logger');

const isMissingUserSessionsTableError = (error) => {
  const message = error?.message || '';
  return error?.code === 'PGRST205'
    || /Could not find the table 'public\.user_sessions' in the schema cache/i.test(message)
    || /relation "?public\.user_sessions"? does not exist/i.test(message);
};

const verifyToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader?.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid Authorization header' });

  const token = authHeader.slice(7);
  let payload;
  try {
    payload = jwt.verify(token, JWT_CONFIG.accessSecret, {
      algorithms: [JWT_CONFIG.algorithm],
      issuer:     JWT_CONFIG.issuer,
      audience:   JWT_CONFIG.audience,
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError')
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    logger.warn('Invalid JWT', { ip: req.ip, err: err.message });
    return res.status(401).json({ error: 'Invalid token' });
  }

  const { data: revoked } = await supabase
    .from('revoked_tokens').select('id').eq('jti', payload.jti).single();
  if (revoked) {
    logger.warn('Revoked token used', { userId: payload.sub, ip: req.ip });
    return res.status(401).json({ error: 'Token has been revoked' });
  }

  req.user = { id: payload.sub, email: payload.email, role: payload.role || 'user', plan: payload.plan || 'free', jti: payload.jti };
  next();
};

const recordSession = async (userId, jti) => {
  const { error } = await supabase.from('user_sessions').upsert({
    user_id: userId,
    jti,
    issued_at: new Date(),
    last_seen_at: new Date(),
    revoked_at: null,
  }, { onConflict: 'jti' });
  if (error && isMissingUserSessionsTableError(error)) {
    logger.warn('user_sessions table unavailable; skipping session persistence', { userId, err: error.message });
    return;
  }
  if (error) throw Object.assign(new Error(error.message || 'Failed to record session'), { status: 500, code: error.code });
};

const revokeSession = async (jti, userId) => {
  const [revokedResult, sessionResult] = await Promise.all([
    supabase.from('revoked_tokens').insert({ jti, user_id: userId }),
    supabase.from('user_sessions').update({ revoked_at: new Date() }).eq('jti', jti).eq('user_id', userId),
  ]);

  if (sessionResult?.error && !isMissingUserSessionsTableError(sessionResult.error)) {
    throw Object.assign(new Error(sessionResult.error.message || 'Failed to revoke session'), { status: 500, code: sessionResult.error.code });
  }

  return revokedResult;
};

const revokeUserSessions = async (userId, currentJti = null) => {
  const { data: sessions, error } = await supabase.from('user_sessions')
    .select('jti')
    .eq('user_id', userId);

  if (error && isMissingUserSessionsTableError(error)) {
    logger.warn('user_sessions table unavailable; skipping tracked session revocation', { userId, err: error.message });
    const jtIs = [...new Set([currentJti].filter(Boolean))];
    if (!jtIs.length) return;
    await supabase.from('revoked_tokens').upsert(
      jtIs.map(jti => ({ jti, user_id: userId })),
      { onConflict: 'jti' }
    );
    return;
  }

  if (error) throw Object.assign(new Error(error.message || 'Failed to load sessions'), { status: 500, code: error.code });

  const jtIs = [...new Set([...(sessions || []).map(s => s.jti), currentJti].filter(Boolean))];
  if (!jtIs.length) return;

  const [revokedResult, sessionUpdateResult] = await Promise.all([
    supabase.from('revoked_tokens').upsert(
      jtIs.map(jti => ({ jti, user_id: userId })),
      { onConflict: 'jti' }
    ),
    supabase.from('user_sessions').update({ revoked_at: new Date() }).eq('user_id', userId),
  ]);

  if (sessionUpdateResult?.error && !isMissingUserSessionsTableError(sessionUpdateResult.error)) {
    throw Object.assign(new Error(sessionUpdateResult.error.message || 'Failed to revoke tracked sessions'), { status: 500, code: sessionUpdateResult.error.code });
  }

  return revokedResult;
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });
  if (!roles.includes(req.user.role)) {
    logger.warn('Unauthorised role access', { userId: req.user.id, required: roles, actual: req.user.role });
    return res.status(403).json({ error: 'Insufficient permissions' });
  }
  next();
};

const PLAN_HIERARCHY = { free: 0, starter: 1, pro: 2, enterprise: 3 };
const requirePlan = (minPlan) => (req, res, next) => {
  if ((PLAN_HIERARCHY[req.user?.plan] ?? 0) < (PLAN_HIERARCHY[minPlan] ?? 0))
    return res.status(403).json({ error: 'Plan upgrade required', required: minPlan, current: req.user?.plan });
  next();
};

const issueTokens = (user) => {
  const jti = uuidv4();
  const accessToken = jwt.sign(
    { email: user.email, role: user.role, plan: user.plan, jti },
    JWT_CONFIG.accessSecret,
    { subject: user.id, expiresIn: JWT_CONFIG.accessExpiresIn, issuer: JWT_CONFIG.issuer, audience: JWT_CONFIG.audience, algorithm: JWT_CONFIG.algorithm }
  );
  const refreshToken = jwt.sign(
    { jti },
    JWT_CONFIG.refreshSecret,
    { subject: user.id, expiresIn: JWT_CONFIG.refreshExpiresIn, issuer: JWT_CONFIG.issuer, audience: JWT_CONFIG.audience, algorithm: JWT_CONFIG.algorithm }
  );
  return { accessToken, refreshToken, jti };
};

const rotateRefreshToken = async (oldRefreshToken) => {
  let payload;
  try {
    payload = jwt.verify(oldRefreshToken, JWT_CONFIG.refreshSecret, {
      algorithms: [JWT_CONFIG.algorithm], issuer: JWT_CONFIG.issuer, audience: JWT_CONFIG.audience,
    });
  } catch { throw Object.assign(new Error('Invalid refresh token'), { status: 401 }); }

  await supabase.from('revoked_tokens').insert({ jti: payload.jti, user_id: payload.sub });
  const { data: user, error } = await supabase
    .from('users').select('id, email, role, plan, is_active').eq('id', payload.sub).single();
  if (error || !user || !user.is_active)
    throw Object.assign(new Error('Account not found or inactive'), { status: 401 });
  return { ...issueTokens(user), userId: user.id };
};

const revokeToken = async (jti, userId) => {
  await revokeSession(jti, userId);
};

module.exports = { verifyToken, requireRole, requirePlan, issueTokens, rotateRefreshToken, revokeToken, recordSession, revokeSession, revokeUserSessions };
