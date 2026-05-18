/**
 * OmniPublish — server.js
 * Production-grade Express server with layered security architecture.
 * Compliance: OWASP Top 10 · GDPR · SOC 2 Type II · CCPA
 */

'use strict';
require('dotenv').config();
require('express-async-errors');

const crypto     = require('crypto');
const fs         = require('fs');
const path       = require('path');
const express     = require('express');
const helmet      = require('helmet');
const cors        = require('cors');
const compression = require('compression');
const morgan      = require('morgan');
const hpp         = require('hpp');
const cron        = require('node-cron');
const passport    = require('passport');

const cookieParser                 = require('cookie-parser');
const { logger, httpLogStream }    = require('./utils/logger');
const { dbSchemaHealthCheck } = require('./config/database');
const { globalRateLimiter }        = require('./middleware/rateLimit');
const { errorHandler }             = require('./middleware/errorHandler');
const { requestSanitizer }         = require('./middleware/sanitizer');
const { auditLogger }              = require('./middleware/audit');
const { verifyCSRF }               = require('./middleware/csrf');
const { securityHeaders }          = require('./config/security');
const { requireApiKey } = require('./middleware/apiKey');
const { idempotencyMiddleware }    = require('./middleware/idempotency');
const { cleanupExpiredOAuthStates } = require('./middleware/oauthStateVerification');

const authRoutes      = require('./routes/auth');
const oauthRoutes     = require('./routes/oauth');
const postsRoutes     = require('./routes/posts');
const platformsRoutes = require('./routes/platforms');
const publishRoutes   = require('./routes/publish');
const mediaRoutes     = require('./routes/media');
const healthRoutes    = require('./routes/health');
const gdprRoutes      = require('./routes/gdpr');

const { processScheduledPosts, cleanupRevokedTokens, executeGdprDeletions } = require('./services/schedulerService');
const { healthReadinessCheck, healthLivenessCheck } = require('./middleware/healthChecks');
const { limiter } = require('./middleware/concurrencyLimit');
const { setupGracefulShutdown } = require('./utils/gracefulShutdown');

const PUBLIC_INDEX_PATH = path.join(__dirname, 'public', 'index.html');
const PUBLIC_INDEX_TEMPLATE = fs.readFileSync(PUBLIC_INDEX_PATH, 'utf8');
const INLINE_EVENT_HANDLER_HASHES = [...new Set([
  ...PUBLIC_INDEX_TEMPLATE.matchAll(/\son[a-z]+="([^"]*)"/gi),
].map(match => match[1].trim()))].map(handler => {
  const digest = crypto.createHash('sha256').update(handler, 'utf8').digest('base64');
  return `'sha256-${digest}'`;
});

const createNonce = () => crypto.randomBytes(16).toString('base64');

const buildCspHeader = (nonce) => {
  const attrHashes = INLINE_EVENT_HANDLER_HASHES.join(' ');
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}'`,
    `script-src-elem 'self' 'nonce-${nonce}'`,
    `script-src-attr 'unsafe-hashes'${attrHashes ? ` ${attrHashes}` : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: *.supabase.co *.cloudfront.net",
    "connect-src 'self' https://api.anthropic.com https://*.supabase.co",
    "media-src 'self' blob: *.cloudfront.net",
    "font-src 'self' https://fonts.gstatic.com",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    'upgrade-insecure-requests',
  ].join('; ');
};

const renderIndexHtml = (nonce) => PUBLIC_INDEX_TEMPLATE.replace('nonce="__CSP_NONCE__"', `nonce="${nonce}"`);

/* ─────────────────────────────────────────
   App bootstrap
───────────────────────────────────────── */
const app = express();

// Trust only the first proxy hop (Nginx / Cloudflare)
app.set('trust proxy', 1);
// Disable fingerprinting header
app.disable('x-powered-by');

/* ─────────────────────────────────────────
   LAYER 1 — Security Headers (Helmet)
   Covers: OWASP A05 · CSP · HSTS · XFO
───────────────────────────────────────── */
app.use((req, res, next) => {
  res.locals.cspNonce = createNonce();
  next();
});

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy:   { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  dnsPrefetchControl:        { allow: false },
  frameguard:                { action: 'deny' },
  hidePoweredBy:             true,
  hsts: {
    maxAge:            31536000,       // 1 year
    includeSubDomains: true,
    preload:           true,
  },
  ieNoOpen:    true,
  noSniff:     true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter:   true,
}));

app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', buildCspHeader(res.locals.cspNonce));
  next();
});

// Extra custom security headers
app.use(securityHeaders);

/* ─────────────────────────────────────────
   LAYER 2 — CORS
   Allowlist-only origins, credential support
───────────────────────────────────────── */
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

const isLocalDevOrigin = origin => /^https?:\/\/(localhost|127(?:\.\d{1,3}){3})(:\d+)?$/.test(origin);

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server (no origin) only in test env
    if (!origin && process.env.NODE_ENV !== 'production') return cb(null, true);
    if (process.env.NODE_ENV !== 'production' && origin && isLocalDevOrigin(origin)) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    logger.warn('CORS rejection', { origin });
    cb(new Error(`CORS: origin ${origin} not permitted`));
  },
  methods:            ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders:     ['Content-Type', 'Authorization', 'X-Request-ID', 'X-CSRF-Token'],
  exposedHeaders:     ['X-Request-ID', 'X-RateLimit-Remaining', 'Retry-After'],
  credentials:        true,
  maxAge:             60,    // preflight cache: 1 min (reduce CORS origin injection window)
  optionsSuccessStatus: 204,
}));

/* ─────────────────────────────────────────
   LAYER 3 — Content-Type Validation
───────────────────────────────────────── */
const validateContentType = (req, res, next) => {
  if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
    const contentType = req.headers['content-type'] || '';
    const contentLength = Number.parseInt(req.headers['content-length'] || '0', 10);
    const hasBody = contentLength > 0 || !!req.headers['transfer-encoding'];
    const isMediaUpload = req.path === '/v1/media/upload' || req.path === '/api/v1/media/upload';

    if (!hasBody) return next();
    if (contentType.includes('application/json')) return next();
    if (isMediaUpload && contentType.includes('multipart/form-data')) return next();

    if (!contentType.includes('application/json')) {
      logger.warn('Invalid content-type', { ip: req.ip, contentType, path: req.path });
      return res.status(415).json({
        error: 'Unsupported Media Type',
        code: 'CONTENT_TYPE_INVALID',
        expected: 'application/json',
        received: contentType,
      });
    }
  }
  next();
};
app.use(validateContentType);

/* ─────────────────────────────────────────
   LAYER 4 — Body Parsing & HTTP Pollution
───────────────────────────────────────── */
app.use(express.json({
  limit: '2mb',         // prevent large payload attacks
  strict: true,         // only arrays/objects
}));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));
app.use(hpp());         // HTTP Parameter Pollution guard
app.use(cookieParser()); // Required for CSRF cookie reading
app.use(passport.initialize());

/* ─────────────────────────────────────────
   LAYER 5 — Compression
───────────────────────────────────────── */
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
  level: 6,
}));

/* ─────────────────────────────────────────
   LAYER 6 — Request Logging (Morgan)
───────────────────────────────────────── */
if (process.env.NODE_ENV !== 'test') {
  app.use(morgan(
    ':remote-addr :method :url :status :res[content-length] - :response-time ms',
    { stream: httpLogStream }
  ));
}

/* ─────────────────────────────────────────
   LAYER 6 — Global Rate Limiting
   Covers: OWASP A04 (Unrestricted Resource Consumption)
───────────────────────────────────────── */
app.use('/api/', globalRateLimiter);

/* ─────────────────────────────────────────
   LAYER 8 — Concurrency Limiting
───────────────────────────────────────── */
app.use('/api/', limiter.middleware(5));

/* ─────────────────────────────────────────
   LAYER 7 — Input Sanitisation (XSS / Injection)
───────────────────────────────────────── */
app.use(requestSanitizer);

/* ─────────────────────────────────────────
   LAYER 8 — CSRF Protection (state-changing routes)
───────────────────────────────────────── */
app.use('/api/', verifyCSRF);

/* ─────────────────────────────────────────
   LAYER 9 — Idempotency Key Verification
───────────────────────────────────────── */
app.use('/api/', idempotencyMiddleware);

/* ─────────────────────────────────────────
   LAYER 10 — Audit Logging
───────────────────────────────────────── */
app.use(auditLogger);

/* ─────────────────────────────────────────
   ROUTES
───────────────────────────────────────── */
app.get('/api/v1/health/live', healthLivenessCheck);
app.get('/api/v1/health/ready', healthReadinessCheck);
app.use('/api/v1/health',     healthRoutes);
app.use('/api/v1/auth',       authRoutes);
app.use('/api/v1/auth',       oauthRoutes);
app.use('/api/v1/gdpr',       gdprRoutes);
app.use('/api/v1/posts',      postsRoutes);
app.use('/api/v1/platforms',  platformsRoutes);
app.use('/api/v1/publish',    publishRoutes);
app.use('/api/v1/media',      mediaRoutes);

// AI endpoints (secure — API key never leaves the server)
const { verifyToken: _vt }    = require('./middleware/auth');
const { aiRateLimiter: _arl } = require('./middleware/rateLimit');
const { validateBody: _vb }   = require('./middleware/sanitizer');
const { aiAdaptContent, aiEnrichContent } = require('./services/aiService');

app.post('/api/v1/ai/adapt',
  _vt, _arl, _vb('adaptContent'),
  async (req, res) => {
    const { content, platforms, format, ratio } = req.body;
    const adapted = await aiAdaptContent({ content, platforms, format, ratio, userId: req.user.id });
    res.json({ adapted });
  }
);

app.post('/api/v1/ai/enrich',
  _vt, _arl, _vb('enrichContent'),
  async (req, res) => {
    const { content, platforms, format, ratio } = req.body;
    const result = await aiEnrichContent({ content, platforms, format, ratio, userId: req.user.id });
    res.json(result);
  }
);
// Admin-only route group — requires API key
app.use('/api/v1/admin', requireApiKey, (req, res) => {
  res.json({ message: 'Admin API', user: req.user });
});

// Serve static UI
app.get(['/', '/index.html'], (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(renderIndexHtml(res.locals.cspNonce));
});

const servePublicPage = (fileName) => (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', fileName));
};

app.get('/terms', servePublicPage('terms.html'));
app.get('/privacy', servePublicPage('privacy.html'));
app.get('/data-deletion', servePublicPage('data-deletion.html'));

app.use(express.static('public'));

// Catch-all 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

/* ─────────────────────────────────────────
   GLOBAL ERROR HANDLER
───────────────────────────────────────── */
app.use(errorHandler);

module.exports = app;

/* ─────────────────────────────────────────
   SERVER START — skipped when imported by tests
───────────────────────────────────────── */
if (require.main === module) {
  // Scheduled jobs
  cron.schedule('* * * * *', async () => {
    try { await processScheduledPosts(); }
    catch (e) { logger.error('Scheduler error', { err: e.message }); }
  });

  cron.schedule('0 * * * *', async () => {
    try { await cleanupRevokedTokens(); }
    catch (e) { logger.error('Token cleanup error', { err: e.message }); }
  });

  cron.schedule('0 * * * *', async () => {
    try { await cleanupExpiredOAuthStates(); }
    catch (e) { logger.error('OAuth state cleanup error', { err: e.message }); }
  });

  // GDPR Art. 17 — purge accounts whose 30-day grace period has elapsed (runs daily at 03:00)
  cron.schedule('0 3 * * *', async () => {
    try { await executeGdprDeletions(); }
    catch (e) { logger.error('GDPR deletion cron error', { err: e.message }); }
  });

  const PORT = parseInt(process.env.PORT || '4000', 10);
  const server = app.listen(PORT, '0.0.0.0', async () => {
    logger.info('OmniPublish API running', {
      port: PORT,
      env:  process.env.NODE_ENV || 'development',
      pid:  process.pid,
    });
    const schema = await dbSchemaHealthCheck();
    if (schema.ok) {
      logger.info('Database ready for MVP', { relations: schema.checks.length });
      if (schema.missingSupportRelations.length) {
        logger.warn('Optional database relations missing', { missingSupportRelations: schema.missingSupportRelations });
      }
    } else {
      logger.error('Database readiness check failed', { missingRelations: schema.missingRelations });
    }
  });

  // Setup graceful shutdown with resource cleanup
  setupGracefulShutdown(server, {
    supabase: null,  // Supabase auto-closes
    redis: null,     // Would be redis client if initialized
  });
}
