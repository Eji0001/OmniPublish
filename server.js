/**
 * OmniPublish — server.js
 * Production-grade Express server with layered security architecture.
 * Compliance: OWASP Top 10 · GDPR · SOC 2 Type II · CCPA
 */

'use strict';
require('dotenv').config();
require('express-async-errors');

const express     = require('express');
const helmet      = require('helmet');
const cors        = require('cors');
const compression = require('compression');
const morgan      = require('morgan');
const hpp         = require('hpp');
const path        = require('path');
const cron        = require('node-cron');

const cookieParser                 = require('cookie-parser');
const { logger, httpLogStream }    = require('./utils/logger');
const { dbHealthCheck }            = require('./config/database');
const { globalRateLimiter }        = require('./middleware/rateLimit');
const { errorHandler }             = require('./middleware/errorHandler');
const { requestSanitizer }         = require('./middleware/sanitizer');
const { auditLogger }              = require('./middleware/audit');
const { verifyCSRF }               = require('./middleware/csrf');
const { securityHeaders }          = require('./config/security');

const authRoutes      = require('./routes/auth');
const postsRoutes     = require('./routes/posts');
const platformsRoutes = require('./routes/platforms');
const publishRoutes   = require('./routes/publish');
const mediaRoutes     = require('./routes/media');
const healthRoutes    = require('./routes/health');

const { processScheduledPosts }    = require('./services/schedulerService');

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
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'strict-dynamic'"],
      styleSrc:       ["'self'", "'unsafe-inline'"],   // tighten when adopting nonce
      imgSrc:         ["'self'", 'data:', 'blob:', '*.supabase.co', '*.cloudfront.net'],
      connectSrc:     ["'self'", 'https://api.anthropic.com', 'https://*.supabase.co'],
      mediaSrc:       ["'self'", 'blob:', '*.cloudfront.net'],
      fontSrc:        ["'self'", 'https://fonts.gstatic.com'],
      objectSrc:      ["'none'"],
      frameSrc:       ["'none'"],
      baseUri:        ["'self'"],
      formAction:     ["'self'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy:   { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-site' },
  dnsPrefetchControl:        { allow: false },
  expectCt:                  { maxAge: 86400, enforce: true },
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

app.use(cors({
  origin: (origin, cb) => {
    // Allow server-to-server (no origin) only in test env
    if (!origin && process.env.NODE_ENV !== 'production') return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    logger.warn('CORS rejection', { origin });
    cb(new Error(`CORS: origin ${origin} not permitted`));
  },
  methods:            ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders:     ['Content-Type', 'Authorization', 'X-Request-ID', 'X-CSRF-Token'],
  exposedHeaders:     ['X-Request-ID', 'X-RateLimit-Remaining', 'Retry-After'],
  credentials:        true,
  maxAge:             600,   // preflight cache: 10 min
  optionsSuccessStatus: 204,
}));

/* ─────────────────────────────────────────
   LAYER 3 — Body Parsing & HTTP Pollution
───────────────────────────────────────── */
app.use(express.json({
  limit: '512kb',       // prevent large payload attacks
  strict: true,         // only arrays/objects
}));
app.use(express.urlencoded({ extended: false, limit: '512kb' }));
app.use(hpp());         // HTTP Parameter Pollution guard
app.use(cookieParser()); // Required for CSRF cookie reading

/* ─────────────────────────────────────────
   LAYER 4 — Compression
───────────────────────────────────────── */
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
  level: 6,
}));

/* ─────────────────────────────────────────
   LAYER 5 — Request Logging (Morgan)
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
   LAYER 7 — Input Sanitisation (XSS / Injection)
───────────────────────────────────────── */
app.use(requestSanitizer);

/* ─────────────────────────────────────────
   LAYER 8 — CSRF Protection (state-changing routes)
───────────────────────────────────────── */
app.use('/api/', verifyCSRF);

/* ─────────────────────────────────────────
   LAYER 9 — Audit Logging
───────────────────────────────────────── */
app.use(auditLogger);

/* ─────────────────────────────────────────
   ROUTES
───────────────────────────────────────── */
app.use('/api/v1/health',     healthRoutes);
app.use('/api/v1/auth',       authRoutes);
app.use('/api/v1/posts',      postsRoutes);
app.use('/api/v1/platforms',  platformsRoutes);
app.use('/api/v1/publish',    publishRoutes);
app.use('/api/v1/media',      mediaRoutes);

// AI adapt endpoint (secure — keeps API key server-side)
app.post('/api/v1/ai/adapt', require('./middleware/auth').verifyToken, require('./middleware/rateLimit').aiRateLimiter, async (req, res) => {
  const { content, platforms, format, ratio } = req.body;
  if (!content || !platforms?.length) return res.status(422).json({ error: 'content and platforms required' });
  const { aiAdaptContent } = require('./services/aiService');
  const adapted = await aiAdaptContent({ content, platforms, format, ratio, userId: req.user.id });
  res.json({ adapted });
});
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

  const PORT = parseInt(process.env.PORT || '4000', 10);
  const server = app.listen(PORT, '0.0.0.0', async () => {
    logger.info('OmniPublish API running', {
      port: PORT,
      env:  process.env.NODE_ENV || 'development',
      pid:  process.pid,
    });
    const isDbConnected = await dbHealthCheck();
    if (isDbConnected) {
      logger.info('Database connected successfully');
    } else {
      logger.error('Failed to connect to the database. Check Supabase credentials.');
    }
  });

  const shutdown = (signal) => {
    logger.info(`${signal} received — graceful shutdown`);
    server.close(() => { logger.info('HTTP server closed'); process.exit(0); });
    setTimeout(() => { logger.error('Forced shutdown after timeout'); process.exit(1); }, 15000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('unhandledRejection', (reason) => {
    logger.error('Unhandled Promise Rejection', { reason: String(reason) });
  });
  process.on('uncaughtException', (err) => {
    logger.error('Uncaught Exception — shutting down', { err: err.message, stack: err.stack });
    process.exit(1);
  });
}
