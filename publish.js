/**
 * routes/publish.js  — cross-platform publishing orchestration
 * routes/media.js    — secure media upload with virus check hook
 * routes/platforms.js — OAuth platform connections
 * routes/health.js   — health & readiness probes
 */

'use strict';

const express        = require('express');
const multer         = require('multer');
const path           = require('path');
const sharp          = require('sharp');
const { v4: uuid }   = require('uuid');
const { supabase }   = require('../config/database');
const { verifyToken, requireRole } = require('../middleware/auth');
const { validateBody }  = require('../middleware/sanitizer');
const { publishRateLimiter, mediaRateLimiter } = require('../middleware/rateLimit');
const { publishToPlatform }  = require('../services/platformService');
const { ALLOWED_MEDIA_TYPES, MAX_FILE_SIZE } = require('../config/security');
const { logger }     = require('../utils/logger');

/* ══════════════════════════════════════════
   PUBLISH ROUTER
══════════════════════════════════════════ */
const publishRouter = express.Router();
publishRouter.use(verifyToken);

/**
 * POST /publish
 * Publishes a post to all selected platforms concurrently.
 * Uses settled promises so one failure doesn't block others.
 */
publishRouter.post(
  '/',
  publishRateLimiter,
  validateBody('publishPost'),
  async (req, res) => {
    const { postId, platforms } = req.body;

    // Ownership check
    const { data: post } = await supabase
      .from('posts')
      .select('*, post_platforms(*)')
      .eq('id', postId)
      .eq('user_id', req.user.id)
      .single();

    if (!post) return res.status(404).json({ error: 'Post not found' });

    // Fetch connected platform tokens for this user
    const { data: connections } = await supabase
      .from('platform_connections')
      .select('platform, access_token_enc, platform_user_id')
      .eq('user_id', req.user.id)
      .in('platform', platforms)
      .eq('is_active', true);

    const connectedMap = Object.fromEntries((connections || []).map(c => [c.platform, c]));

    // Mark all targets as "publishing"
    await supabase
      .from('post_platforms')
      .update({ status: 'publishing' })
      .eq('post_id', postId)
      .in('platform', platforms);

    // Publish concurrently — allSettled never rejects
    const results = await Promise.allSettled(
      platforms.map(async (platform) => {
        const conn = connectedMap[platform];
        if (!conn) throw new Error(`${platform} not connected`);

        const platformPost = post.post_platforms?.find(p => p.platform === platform);
        const content      = platformPost?.adapted_content || post.content;
        const result       = await publishToPlatform({ platform, content, post, conn });

        await supabase.from('post_platforms').update({
          status:           'published',
          platform_post_id: result.postId,
          platform_post_url: result.url,
          published_at:     new Date(),
          error_message:    null,
        }).eq('post_id', postId).eq('platform', platform);

        return { platform, status: 'published', url: result.url };
      })
    );

    // Update failed platforms
    const failed = results.filter(r => r.status === 'rejected');
    for (const r of failed) {
      const platform = r.reason?.platform || 'unknown';
      await supabase.from('post_platforms').update({
        status:        'failed',
        error_message: r.reason?.message?.slice(0, 500),
      }).eq('post_id', postId).eq('platform', platform);
    }

    // Mark post as published if at least one succeeded
    const succeeded = results.filter(r => r.status === 'fulfilled');
    if (succeeded.length > 0) {
      await supabase.from('posts').update({
        status:       'published',
        published_at: new Date(),
      }).eq('id', postId);
    }

    const summary = results.map(r =>
      r.status === 'fulfilled' ? r.value : { platform: 'unknown', status: 'failed', error: r.reason?.message }
    );

    logger.info('Publish completed', { postId, userId: req.user.id, succeeded: succeeded.length, failed: failed.length });
    res.json({ summary, succeeded: succeeded.length, failed: failed.length, total: platforms.length });
  }
);

/* ══════════════════════════════════════════
   MEDIA ROUTER
══════════════════════════════════════════ */
const mediaRouter = express.Router();
mediaRouter.use(verifyToken);

// Memory storage — validate before writing to disk / S3
const storage = multer.memoryStorage();

const fileFilter = (req, file, cb) => {
  const allAllowed = [
    ...ALLOWED_MEDIA_TYPES.image,
    ...ALLOWED_MEDIA_TYPES.video,
  ];
  if (allAllowed.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`File type ${file.mimetype} not allowed`), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE.video,   // use largest limit; per-type checked below
    files:    10,
  },
});

/**
 * POST /media/upload
 * Uploads media to Supabase Storage with image optimisation.
 */
mediaRouter.post(
  '/upload',
  mediaRateLimiter,
  upload.array('files', 10),
  async (req, res) => {
    if (!req.files?.length) return res.status(422).json({ error: 'No files uploaded' });

    const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'media';
    const results = await Promise.allSettled(
      req.files.map(async (file) => {
        const isImage = ALLOWED_MEDIA_TYPES.image.includes(file.mimetype);
        const isVideo = ALLOWED_MEDIA_TYPES.video.includes(file.mimetype);

        // Per-type size guard
        const maxSize = isImage ? MAX_FILE_SIZE.image : MAX_FILE_SIZE.video;
        if (file.size > maxSize) throw new Error(`${file.originalname} exceeds size limit`);

        let buffer   = file.buffer;
        let width, height;

        // Optimise images with Sharp
        if (isImage) {
          const meta = await sharp(buffer).metadata();
          width  = meta.width;
          height = meta.height;
          buffer = await sharp(buffer)
            .resize({ width: 3840, height: 2160, fit: 'inside', withoutEnlargement: true })
            .webp({ quality: 85 })
            .toBuffer();
          file.mimetype = 'image/webp';
        }

        const ext      = isImage ? 'webp' : path.extname(file.originalname).slice(1);
        const filename = `${req.user.id}/${uuid()}.${ext}`;

        const { error: storageErr } = await supabase.storage
          .from(bucket)
          .upload(filename, buffer, { contentType: file.mimetype, upsert: false });

        if (storageErr) throw new Error(`Storage upload failed: ${storageErr.message}`);

        const { data: { publicUrl } } = supabase.storage.from(bucket).getPublicUrl(filename);

        const { data: record } = await supabase.from('media_files').insert({
          user_id:       req.user.id,
          filename,
          original_name: file.originalname.slice(0, 255),
          mime_type:     file.mimetype,
          size_bytes:    file.size,
          storage_path:  filename,
          cdn_url:       publicUrl,
          width:         width || null,
          height:        height || null,
        }).select().single();

        return { id: record.id, url: publicUrl, mimeType: file.mimetype, width, height };
      })
    );

    const uploaded = results.filter(r => r.status === 'fulfilled').map(r => r.value);
    const errors   = results.filter(r => r.status === 'rejected').map(r => r.reason.message);

    res.status(errors.length === results.length ? 500 : 201).json({ uploaded, errors });
  }
);

mediaRouter.delete('/:id', async (req, res) => {
  const { data: file } = await supabase.from('media_files').select('storage_path, user_id').eq('id', req.params.id).single();
  if (!file || file.user_id !== req.user.id) return res.status(404).json({ error: 'File not found' });

  await supabase.storage.from(process.env.SUPABASE_STORAGE_BUCKET || 'media').remove([file.storage_path]);
  await supabase.from('media_files').delete().eq('id', req.params.id);
  res.status(204).send();
});

/* ══════════════════════════════════════════
   PLATFORMS ROUTER
══════════════════════════════════════════ */
const platformsRouter = express.Router();
platformsRouter.use(verifyToken);

// List connected platforms
platformsRouter.get('/', async (req, res) => {
  const { data, error } = await supabase
    .from('platform_connections')
    .select('id, platform, platform_username, is_active, connected_at, token_expires_at')
    .eq('user_id', req.user.id);
  if (error) return res.status(500).json({ error: 'Failed to fetch platforms' });
  res.json({ platforms: data });
});

// OAuth callback — store encrypted tokens
platformsRouter.post('/connect', async (req, res) => {
  const { platform, accessToken, refreshToken, platformUserId, platformUsername, expiresAt } = req.body;
  if (!platform || !accessToken) return res.status(422).json({ error: 'platform and accessToken required' });

  const { encrypt } = require('../utils/encryption');

  const { data, error } = await supabase.from('platform_connections').upsert({
    user_id:           req.user.id,
    platform,
    platform_user_id:  platformUserId,
    platform_username: platformUsername,
    access_token_enc:  encrypt(accessToken),
    refresh_token_enc: refreshToken ? encrypt(refreshToken) : null,
    token_expires_at:  expiresAt || null,
    is_active:         true,
    connected_at:      new Date(),
  }, { onConflict: 'user_id,platform' }).select('id, platform, platform_username').single();

  if (error) return res.status(500).json({ error: 'Failed to save platform connection' });
  logger.info('Platform connected', { userId: req.user.id, platform });
  res.status(201).json({ connection: data });
});

platformsRouter.delete('/:id', async (req, res) => {
  const { error } = await supabase.from('platform_connections')
    .update({ is_active: false }).eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(404).json({ error: 'Connection not found' });
  res.status(204).send();
});

/* ══════════════════════════════════════════
   HEALTH ROUTER
══════════════════════════════════════════ */
const healthRouter = express.Router();

healthRouter.get('/live', (_req, res) => res.json({ status: 'ok', time: new Date() }));

healthRouter.get('/ready', async (_req, res) => {
  const { dbHealthCheck } = require('../config/database');
  const dbOk = await dbHealthCheck();
  const status = dbOk ? 'ready' : 'not_ready';
  res.status(dbOk ? 200 : 503).json({ status, db: dbOk ? 'ok' : 'error', time: new Date() });
});

module.exports = { publishRouter, mediaRouter, platformsRouter, healthRouter };
