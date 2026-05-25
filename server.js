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
const aiRoutes        = require('./routes/ai');

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
const isLocalDevHost = (host) => /^(localhost|127(?:\.\d{1,3}){3}|\[::1\]|::1)$/i.test(String(host || '').trim());

const buildCspHeader = (nonce) => {
  const attrHashes = INLINE_EVENT_HANDLER_HASHES.join(' ');
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://sdk.snapkit.com`,
    `script-src-elem 'self' 'nonce-${nonce}' https://sdk.snapkit.com`,
    `script-src-attr 'unsafe-hashes'${attrHashes ? ` ${attrHashes}` : ''}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https: *.supabase.co *.cloudfront.net",
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

const renderIndexHtml = (nonce, { demoMode = false, edgeProxyUrl = '' } = {}) => {
  const initialHomeClass = demoMode ? 'page active' : 'page';
  const initialDashboardClass = demoMode ? 'page' : 'page active';

  return PUBLIC_INDEX_TEMPLATE
    .replace('nonce="__CSP_NONCE__"', `nonce="${nonce}"`)
    .replace('<div id="page-home" class="page active">', `<div id="page-home" class="${initialHomeClass}">`)
    .replace('<div id="page-dashboard" class="page">', `<div id="page-dashboard" class="${initialDashboardClass}">`)
    .replace('__OMNIPUBLISH_DEMO_MODE_VALUE__', demoMode ? 'true' : 'false')
    .replace('__OMNIPUBLISH_EDGE_PROXY_URL_VALUE__', JSON.stringify(edgeProxyUrl));
};

const escapeHtml = (value) => String(value ?? '')
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const truncateText = (value, max) => String(value ?? '').trim().slice(0, max);

const getAppBaseUrl = (req) => process.env.APP_URL || `${req.protocol}://${req.get('host')}`;

const buildSnapchatShareHtml = ({ pageUrl, title, description, imageUrl, appId, publisherId }) => `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta property="og:site_name" content="OmniPublish">
  <meta property="og:type" content="website">
  <meta property="og:url" content="${escapeHtml(pageUrl)}">
  <meta property="og:title" content="${escapeHtml(title)}">
  <meta property="og:description" content="${escapeHtml(description)}">
  <meta property="og:image" content="${escapeHtml(imageUrl)}">
  <meta property="snapchat:sticker" content="${escapeHtml(imageUrl)}">
  <meta name="twitter:card" content="summary_large_image">
  ${appId ? `<meta property="snapchat:app_id" content="${escapeHtml(appId)}">` : ''}
  ${publisherId ? `<meta property="snapchat:publisher_id" content="${escapeHtml(publisherId)}">` : ''}
  <title>${escapeHtml(title)} · Snapchat Share</title>
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <style>
    :root{color-scheme:dark;--bg:#08111f;--card:#10192d;--card2:#0c1526;--tx:#eef3ff;--tx2:#b7c4e3;--bd:rgba(255,255,255,.08);--acc:#3d7cff;--grad:linear-gradient(135deg,#3d7cff,#7a4dff)}
    *{box-sizing:border-box}
    body{margin:0;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(circle at top,#172746 0,#08111f 58%);color:var(--tx)}
    main{max-width:920px;margin:0 auto;padding:40px 20px 56px}
    .card{background:linear-gradient(180deg,rgba(16,25,45,.96),rgba(12,21,38,.96));border:1px solid var(--bd);border-radius:24px;padding:28px;box-shadow:0 24px 60px rgba(0,0,0,.28)}
    .top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:24px;flex-wrap:wrap}
    .brand{display:flex;align-items:center;gap:10px;font-weight:800;font-size:18px}
    .mark{width:32px;height:32px;border-radius:10px;overflow:hidden;display:grid;place-items:center;background:var(--grad)}
    .mark img{width:100%;height:100%;object-fit:contain;display:block}
    h1{margin:0 0 8px;font-size:clamp(1.8rem,4vw,2.8rem);line-height:1.08}
    p{color:var(--tx2);line-height:1.6}
    .preview{display:grid;grid-template-columns:120px 1fr;gap:16px;align-items:center;background:rgba(255,255,255,.03);border:1px solid var(--bd);border-radius:18px;padding:16px;margin:20px 0}
    .preview img{width:120px;height:120px;object-fit:cover;border-radius:16px;background:#fff}
    .btn-wrap{margin-top:24px;display:flex;justify-content:center}
    .snapchat-share-button{display:inline-flex;align-items:center;justify-content:center;min-width:240px;min-height:56px}
    .hint{font-size:13px;color:var(--tx2);text-align:center;margin-top:14px}
    .meta{margin-top:18px;color:#8ea0c7;font-size:12px;text-align:center;word-break:break-all}
    @media (max-width:640px){.preview{grid-template-columns:1fr}.preview img{width:100%;height:auto;aspect-ratio:1/1}}
  </style>
</head>
<body>
  <main>
    <section class="card">
      <div class="top">
        <div class="brand"><span class="mark"><img src="/favicon.svg" alt="" aria-hidden="true"></span><span>OmniPublish</span></div>
        <a href="/" style="color:var(--tx2);text-decoration:none;border:1px solid var(--bd);padding:10px 14px;border-radius:999px;background:rgba(255,255,255,.03)">Back to app</a>
      </div>
      <h1>${escapeHtml(title)}</h1>
      <p>${escapeHtml(description)}</p>
      <div class="preview">
        <img src="${escapeHtml(imageUrl)}" alt="Snapchat share preview">
        <div>
          <strong>${escapeHtml(title)}</strong>
          <p style="margin:8px 0 0">Open Snapchat to share this OmniPublish post.</p>
        </div>
      </div>
      <div class="btn-wrap">
        <div class="snapchat-share-button snapchat-creative-kit-share" data-theme="dark" data-size="large" data-text="true" data-share-url="${escapeHtml(pageUrl)}"></div>
      </div>
      <div class="hint">If the button does not load, allow Creative Kit for this domain in Snap Developer Portal.</div>
      <div class="meta">Share URL: ${escapeHtml(pageUrl)}</div>
    </section>
  </main>
  <script src="/js/snapchat-share.js" defer></script>
</body>
</html>`;

const buildSnapchatSharePageUrl = (baseUrl, { title, description, image, appId, publisherId }) => {
  const url = new URL('/snapchat/share', baseUrl);
  if (title) url.searchParams.set('title', title);
  if (description) url.searchParams.set('description', description);
  if (image) url.searchParams.set('image', image);
  if (appId) url.searchParams.set('appId', appId);
  if (publisherId) url.searchParams.set('publisherId', publisherId);
  return url.toString();
};

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

// Same-origin requests from the locally-served page always include Origin even in production.
// Derive the server's own local origins so they're never rejected.
const _serverPort = parseInt(process.env.PORT || '4000', 10);
const SELF_ORIGINS = new Set([
  `http://localhost:${_serverPort}`,
  `http://127.0.0.1:${_serverPort}`,
]);

app.use(cors({
  origin: (origin, cb) => {
    // No-origin requests (direct browser navigation, curl, Postman) are not a CORS attack vector
    if (!origin) return cb(null, true);
    // Same-origin requests from the server's own frontend are always allowed
    if (SELF_ORIGINS.has(origin)) return cb(null, true);
    if (process.env.NODE_ENV !== 'production' && isLocalDevOrigin(origin)) return cb(null, true);
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
app.use('/api/v1/ai',         aiRoutes);

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
  const demoMode = process.env.OMNIPUBLISH_DEMO_MODE === 'true' || isLocalDevHost(req.hostname);
  res.type('html').send(renderIndexHtml(res.locals.cspNonce, {
    demoMode,
    edgeProxyUrl: process.env.OMNIPUBLISH_EDGE_PROXY_URL || '',
  }));
});

const servePublicPage = (fileName) => (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'public', fileName));
};

app.get('/terms', servePublicPage('terms.html'));
app.get('/privacy', servePublicPage('privacy.html'));
app.get('/data-deletion', servePublicPage('data-deletion.html'));
app.get(['/brand', '/logo-downloads'], (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "connect-src 'none'",
    "object-src 'none'",
    "frame-src 'none'",
    "base-uri 'self'",
  ].join('; '));
  res.sendFile(path.join(__dirname, 'public', 'logo-downloads.html'));
});

app.get('/snapchat/share', (req, res) => {
  const baseUrl = getAppBaseUrl(req);
  const title = truncateText(req.query.title || 'Share on Snapchat', 120) || 'Share on Snapchat';
  const description = truncateText(req.query.description || 'Open this OmniPublish post in Snapchat.', 220) || 'Open this OmniPublish post in Snapchat.';
  const imageCandidate = String(req.query.image || '').trim();
  const imageUrl = imageCandidate ? (imageCandidate.startsWith('http://') || imageCandidate.startsWith('https://')
    ? imageCandidate
    : new URL(imageCandidate, baseUrl).toString())
    : new URL('/favicon.png', baseUrl).toString();
  const appId = truncateText(req.query.appId || process.env.SNAPCHAT_APP_ID || '', 120);
  const publisherId = truncateText(req.query.publisherId || process.env.SNAPCHAT_PUBLISHER_ID || '', 120);
  const pageUrl = buildSnapchatSharePageUrl(baseUrl, { title, description, image: imageCandidate || undefined, appId: appId || undefined, publisherId: publisherId || undefined });

  res.setHeader('Cache-Control', 'no-store');
  res.type('html').send(buildSnapchatShareHtml({
    pageUrl,
    title,
    description,
    imageUrl,
    appId,
    publisherId,
  }));
});

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
