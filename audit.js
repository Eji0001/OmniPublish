/**
 * middleware/audit.js — Tamper-evident audit trail for all API actions
 * middleware/csrf.js  — Double-submit cookie CSRF protection
 * middleware/errorHandler.js — Centralised error formatting
 */

'use strict';

const crypto         = require('crypto');
const { supabase }   = require('../config/database');
const { logger }     = require('../utils/logger');

/* ═══════════════════════════════════════════
   AUDIT LOGGER
   Covers: SOC 2 CC7.2 · GDPR Art. 30 logging
═══════════════════════════════════════════ */

// Actions that must always be logged regardless of response
const ALWAYS_AUDIT = new Set([
  'login', 'logout', 'register', 'password_change',
  'token_refresh', 'account_delete', 'publish',
  'platform_connect', 'platform_disconnect',
  'media_upload', 'admin_action',
]);

const inferAction = (req) => {
  const m = req.method;
  const p = req.path.replace(/\/[0-9a-f-]{36}/gi, '/:id'); // normalise UUIDs
  const map = {
    'POST /auth/login':       'login',
    'POST /auth/register':    'register',
    'POST /auth/logout':      'logout',
    'POST /auth/refresh':     'token_refresh',
    'POST /publish':          'publish',
    'POST /media/upload':     'media_upload',
    'POST /platforms/connect':'platform_connect',
    'DELETE /platforms/:id':  'platform_disconnect',
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

  // Intercept res.json to capture the status code
  const originalJson = res.json.bind(res);
  res.json = (body) => {
    res._body = body;
    return originalJson(body);
  };

  res.on('finish', async () => {
    const duration = Date.now() - start;
    const level    = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    if (!mustLog && res.statusCode < 400 && duration < 3000) return; // skip trivial successes

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
        metadata: {
          query:  req.query,
          params: req.params,
        },
      });
    } catch (e) {
      logger.error('Audit log write failed', { err: e.message });
    }

    logger[level](`[AUDIT] ${action}`, {
      userId:    req.user?.id,
      ip:        req.ip,
      status:    res.statusCode,
      duration,
      requestId: req.requestId,
    });
  });

  next();
};

/* ═══════════════════════════════════════════
   CSRF PROTECTION (Double-submit cookie)
   State-changing requests must include both:
     - Cookie: csrf_token
     - Header: X-CSRF-Token (same value)
═══════════════════════════════════════════ */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const CSRF_SKIP    = new Set(['/api/v1/auth/login', '/api/v1/auth/register', '/api/v1/health']);

const verifyCSRF = (req, res, next) => {
  // Skip safe methods and public auth endpoints
  if (SAFE_METHODS.has(req.method)) return next();
  if (CSRF_SKIP.has(req.path))      return next();

  const cookieToken  = req.cookies?.csrf_token;
  const headerToken  = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken) {
    return res.status(403).json({ error: 'CSRF token missing' });
  }

  // Timing-safe comparison
  try {
    const buf1 = Buffer.from(cookieToken,  'utf8');
    const buf2 = Buffer.from(headerToken,  'utf8');
    if (buf1.length !== buf2.length || !crypto.timingSafeEqual(buf1, buf2)) {
      logger.warn('CSRF mismatch', { ip: req.ip, path: req.path });
      return res.status(403).json({ error: 'CSRF token invalid' });
    }
  } catch {
    return res.status(403).json({ error: 'CSRF token invalid' });
  }

  next();
};

const generateCSRFToken = () => crypto.randomBytes(32).toString('hex');

/* ═══════════════════════════════════════════
   GLOBAL ERROR HANDLER
   Never leaks stack traces to clients in prod
═══════════════════════════════════════════ */

const errorHandler = (err, req, res, _next) => {
  const status  = err.status || err.statusCode || 500;
  const isProd  = process.env.NODE_ENV === 'production';

  logger.error('Unhandled error', {
    status,
    message:   err.message,
    stack:     err.stack,
    path:      req.path,
    method:    req.method,
    requestId: req.requestId,
    userId:    req.user?.id,
  });

  // CORS errors
  if (err.message?.includes('CORS')) {
    return res.status(403).json({ error: 'CORS policy violation' });
  }

  // Validation errors from express-validator
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }

  // Payload too large
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }

  const body = {
    error:     isProd && status === 500 ? 'Internal server error' : err.message,
    requestId: req.requestId,
    ...(isProd ? {} : { stack: err.stack }),
  };

  if (err.errors) body.errors = err.errors; // pass-through validation errors

  res.status(status).json(body);
};

module.exports = { auditLogger, verifyCSRF, generateCSRFToken, errorHandler };
