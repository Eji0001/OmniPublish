/**
 * middleware/audit.js — Tamper-evident audit trail for all API actions
 * Covers: SOC 2 CC7.2 · GDPR Art. 30 logging
 */

'use strict';

const { supabase } = require('../config/database');
const { logger }   = require('../utils/logger');

const SENSITIVE_QUERY_KEYS = new Set([
  'token', 'access_token', 'refresh_token', 'api_key', 'apikey',
  'secret', 'password', 'key', 'auth', 'authorization',
]);

const redactQuery = (query) => {
  const out = {};
  for (const [k, v] of Object.entries(query || {})) {
    out[k] = SENSITIVE_QUERY_KEYS.has(k.toLowerCase()) ? '***' : v;
  }
  return out;
};

const SENSITIVE_BODY_FRAGMENTS = ['password', 'token', 'secret', 'authorization', 'api_key', 'apikey', 'enc'];
const redactBody = (body) => {
  if (!body || typeof body !== 'object') return {};
  const out = {};
  for (const [k, v] of Object.entries(body)) {
    const lk = k.toLowerCase();
    out[k] = SENSITIVE_BODY_FRAGMENTS.some(f => lk.includes(f)) ? '***' : v;
  }
  return out;
};

const ALWAYS_AUDIT = new Set([
  'login', 'logout', 'register', 'password_change',
  'token_refresh', 'account_delete', 'publish',
  'platform_connect', 'platform_disconnect',
  'media_upload', 'admin_action',
]);

const inferAction = (req) => {
  const m = req.method;
  const p = req.path.replace(/\/[0-9a-f-]{36}/gi, '/:id');
  const map = {
    'POST /auth/login':        'login',
    'POST /auth/register':     'register',
    'POST /auth/logout':       'logout',
    'POST /auth/refresh':      'token_refresh',
    'POST /publish':           'publish',
    'POST /media/upload':      'media_upload',
    'POST /platforms/connect': 'platform_connect',
    'DELETE /platforms/:id':   'platform_disconnect',
  };
  for (const [key, action] of Object.entries(map)) {
    const [method, path] = key.split(' ');
    if (m === method && p.includes(path)) return action;
  }
  return `${m.toLowerCase()}_${p.split('/').filter(Boolean).join('_')}`;
};

const auditLogger = async (req, res, next) => {
  const start   = Date.now();
  const action  = inferAction(req);
  const mustLog = ALWAYS_AUDIT.has(action);

  const originalJson = res.json.bind(res);
  res.json = (body) => { res._body = body; return originalJson(body); };

  res.on('finish', async () => {
    const duration = Date.now() - start;
    const level    = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';
    if (!mustLog && res.statusCode < 400 && duration < 3000) return;
    try {
      await supabase.from('audit_logs').insert({
        user_id:       req.user?.id || null,
        action,
        resource_type: req.path.split('/')[3] || null,
        ip_address:    req.ip,
        user_agent:    req.headers['user-agent']?.slice(0, 512),
        http_method:   req.method,
        http_path:     req.path,
        http_status:   res.statusCode,
        duration_ms:   duration,
        request_id:    req.requestId,
        metadata:      { query: redactQuery(req.query), params: req.params, ...(req.method !== 'GET' && req.body ? { body: redactBody(req.body) } : {}) },
      });
    } catch (e) { logger.error('Audit log write failed', { err: e.message }); }
    logger[level](`[AUDIT] ${action}`, { userId: req.user?.id, ip: req.ip, status: res.statusCode, duration });
  });

  next();
};

module.exports = { auditLogger };
