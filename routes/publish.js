/**
 * routes/publish.js — Cross-platform publishing orchestration
 */

'use strict';

const express                  = require('express');
const { supabase }             = require('../config/database');
const { verifyToken }          = require('../middleware/auth');
const { validateBody }         = require('../middleware/sanitizer');
const { publishRateLimiter }   = require('../middleware/rateLimit');
const { publishToPlatform }    = require('../services/platformService');
const { logger }               = require('../utils/logger');

const router = express.Router();
router.use(verifyToken);
const getDb = (req) => req.db || supabase;

const buildPlatformPostPayload = (post, platform) => {
  const platformPost = post.post_platforms?.find(p => p.platform === platform);
  return {
    ...post,
    media_url: platformPost?.custom_media_url || post.media_files?.[0]?.cdn_url || null,
  };
};

/**
 * POST /publish — publish a post to all selected platforms concurrently.
 * Uses Promise.allSettled so one failure doesn't block others.
 */
router.post('/', publishRateLimiter, validateBody('publishPost'), async (req, res) => {
  const { postId, platforms } = req.body;
  const db = getDb(req);

  // Ownership check via scoped client — req.db auto-scopes to req.user.id
  const { data: post } = await db.from('posts')
    .select('*, post_platforms(*), media_files(cdn_url)')
    .eq('id', postId).single();
  if (!post) return res.status(404).json({ error: 'Post not found' });

  // Fetch connected platform tokens (scoped to user)
  const { data: connections } = await db.from('platform_connections')
    .select('id, platform, access_token_enc, refresh_token_enc, platform_user_id, token_expires_at')
    .in('platform', platforms).eq('is_active', true);

  const connectedMap = Object.fromEntries((connections || []).map(c => [c.platform, c]));

  // Mark all targets as "publishing"
  await db.from('post_platforms').update({ status: 'publishing' }).eq('post_id', postId).in('platform', platforms);

  // Publish concurrently
  const results = await Promise.allSettled(
    platforms.map(async (platform) => {
      const conn = connectedMap[platform];
      if (!conn) throw Object.assign(new Error(`${platform} not connected`), { platform });

      const platformPost = post.post_platforms?.find(p => p.platform === platform);
      const content      = platformPost?.adapted_content || post.content;
      const result       = await publishToPlatform({
        platform,
        content,
        post: buildPlatformPostPayload(post, platform),
        conn,
        persistConnectionTokens: async (updates) => {
          await db.from('platform_connections')
            .update(updates).eq('id', conn.id).eq('user_id', req.user.id);
        },
      });

      await db.from('post_platforms').update({
        status: 'published', platform_post_id: result.postId,
        platform_post_url: result.url, published_at: new Date(), error_message: null,
      }).eq('post_id', postId).eq('platform', platform);

      return { platform, status: 'published', url: result.url };
    })
  );

  // Update failed platforms
  const failed = results.filter(r => r.status === 'rejected');
  for (const r of failed) {
    const platform = r.reason?.platform || 'unknown';
    await db.from('post_platforms').update({
      status: 'failed', error_message: r.reason?.message?.slice(0, 500),
    }).eq('post_id', postId).eq('platform', platform);
  }

  const succeeded = results.filter(r => r.status === 'fulfilled');
  if (succeeded.length > 0) {
    await db.from('posts').update({ status: 'published', published_at: new Date() }).eq('id', postId);
  }

  const summary = results.map(r =>
    r.status === 'fulfilled' ? r.value : { platform: r.reason?.platform || 'unknown', status: 'failed', error: r.reason?.message }
  );

  logger.info('Publish completed', { postId, userId: req.user.id, succeeded: succeeded.length, failed: failed.length });
  res.json({ summary, succeeded: succeeded.length, failed: failed.length, total: platforms.length });
});

module.exports = router;
