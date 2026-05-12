/**
 * routes/posts.js
 * Post management: create · read · update · delete · AI adapt
 */

'use strict';

const express            = require('express');
const { supabase }       = require('../config/database');
const { verifyToken }    = require('../middleware/auth');
const { validateBody }   = require('../middleware/sanitizer');
const { aiRateLimiter }  = require('../middleware/rateLimit');
const { aiAdaptContent } = require('../services/aiService');
const { logger }         = require('../utils/logger');

const router = express.Router();
router.use(verifyToken);

/* ── GET /posts ── */
router.get('/', async (req, res) => {
  const { status, format } = req.query;
  const page = Math.max(1, Math.min(999, parseInt(req.query.page) || 1));
  const limit = Math.max(1, Math.min(100, parseInt(req.query.limit) || 20));

  const offset = (page - 1) * limit;
  let query = supabase.from('posts')
    .select('id,title,content,format,aspect_ratio,status,scheduled_at,published_at,created_at,post_platforms(platform,status,platform_post_url,published_at)', { count: 'exact' })
    .eq('user_id', req.user.id).order('created_at', { ascending: false })
    .range(offset, offset + limit - 1);
  if (status) query = query.eq('status', status);
  if (format) query = query.eq('format', format);
  const { data, error, count } = await query;
  if (error) return res.status(500).json({ error: 'Failed to fetch posts' });
  res.json({ posts: data, total: count, page, limit });
});

/* ── GET /posts/stats/overview — must be before /:id ── */
router.get('/stats/overview', async (req, res) => {
  const { data: userPosts } = await supabase
    .from('posts').select('id, status').eq('user_id', req.user.id);
  const postIds = (userPosts || []).map(p => p.id);
  const { data: byPlatform } = postIds.length
    ? await supabase.from('post_platforms').select('platform, status').in('post_id', postIds)
    : { data: [] };
  const counts = (userPosts || []).reduce((acc, p) => { acc[p.status] = (acc[p.status] || 0) + 1; return acc; }, {});
  const platformStats = (byPlatform || []).reduce((acc, p) => {
    if (!acc[p.platform]) acc[p.platform] = { total: 0, published: 0, failed: 0 };
    acc[p.platform].total++;
    if (p.status === 'published') acc[p.platform].published++;
    if (p.status === 'failed')    acc[p.platform].failed++;
    return acc;
  }, {});
  res.json({ statusCounts: counts, platformStats });
});

/* ── POST /posts/adapt — must be before /:id ── */
router.post('/adapt', aiRateLimiter, validateBody('adaptContent'), async (req, res) => {
  const { content, platforms, format, ratio } = req.body;
  const adapted = await aiAdaptContent({ content, platforms, format, ratio, userId: req.user.id });
  res.json({ adapted });
});

/* ── GET /posts/:id ── */
router.get('/:id', async (req, res) => {
  const { data: post, error } = await supabase.from('posts')
    .select('*, post_platforms(*), media_files(*)')
    .eq('id', req.params.id).eq('user_id', req.user.id).single();
  if (error || !post) return res.status(404).json({ error: 'Post not found' });
  res.json({ post });
});

/* ── POST /posts ── */
router.post('/', validateBody('createPost'), async (req, res) => {
  const { content, title, format, aspectRatio, scheduledAt, platforms, mediaIds } = req.body;
  const { data: post, error } = await supabase.from('posts')
    .insert({ user_id: req.user.id, title: title || null, content, format: format || 'post', aspect_ratio: aspectRatio || '16:9', status: scheduledAt ? 'scheduled' : 'draft', scheduled_at: scheduledAt || null })
    .select().single();
  if (error) { logger.error('Create post error', { err: error.message }); return res.status(500).json({ error: 'Failed to create post' }); }
  if (platforms?.length) await supabase.from('post_platforms').insert(platforms.map(p => ({ post_id: post.id, platform: p, status: 'pending' })));
  if (mediaIds?.length) await supabase.from('media_files').update({ post_id: post.id }).in('id', mediaIds).eq('user_id', req.user.id);
  res.status(201).json({ post });
});

/* ── PATCH /posts/:id ── */
router.patch('/:id', validateBody('patchPost'), async (req, res) => {
  const allowed = ['title', 'content', 'format', 'aspect_ratio', 'scheduled_at', 'status'];
  const updates = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
  updates.updated_at = new Date();
  const { data: post, error } = await supabase.from('posts').update(updates).eq('id', req.params.id).eq('user_id', req.user.id).select().single();
  if (error || !post) return res.status(404).json({ error: 'Post not found or update failed' });
  res.json({ post });
});

/* ── DELETE /posts/:id ── */
router.delete('/:id', async (req, res) => {
  const bucket = process.env.SUPABASE_STORAGE_BUCKET || 'media';
  const { data: mediaFiles } = await supabase.from('media_files')
    .select('storage_path')
    .eq('post_id', req.params.id)
    .eq('user_id', req.user.id);

  const { error } = await supabase.from('posts').delete().eq('id', req.params.id).eq('user_id', req.user.id);
  if (error) return res.status(404).json({ error: 'Post not found' });

  const storagePaths = (mediaFiles || []).map(file => file.storage_path).filter(Boolean);
  if (storagePaths.length) {
    const { error: storageError } = await supabase.storage.from(bucket).remove(storagePaths);
    if (storageError) {
      logger.warn('Failed to remove post media from storage', {
        postId: req.params.id,
        userId: req.user.id,
        err: storageError.message,
      });
    }
  }

  res.status(204).send();
});

module.exports = router;
