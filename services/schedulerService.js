/**
 * services/schedulerService.js — Processes scheduled posts
 * Runs on a cron every minute from server.js
 */

'use strict';

const { supabase }          = require('../config/database');
const { publishToPlatform } = require('./platformService');
const { logger }            = require('../utils/logger');

const processScheduledPosts = async () => {
  const { data: duePosts } = await supabase
    .from('posts')
    .select('id, user_id, content, title, media_url, link_url, post_platforms(platform)')
    .eq('status', 'scheduled')
    .lte('scheduled_at', new Date().toISOString())
    .limit(20);

  if (!duePosts?.length) return;
  logger.info(`Processing ${duePosts.length} scheduled post(s)`);

  for (const post of duePosts) {
    const platforms = (post.post_platforms || []).map(p => p.platform);
    if (!platforms.length) continue;

    try {
      const { data: connections } = await supabase
        .from('platform_connections')
        .select('platform, access_token_enc, platform_user_id')
        .eq('user_id', post.user_id)
        .in('platform', platforms)
        .eq('is_active', true);

      const connMap = Object.fromEntries((connections || []).map(c => [c.platform, c]));

      const results = await Promise.allSettled(
        platforms.map(pl => {
          const conn = connMap[pl];
          if (!conn) return Promise.reject(Object.assign(new Error(`${pl} not connected`), { platform: pl }));
          return publishToPlatform({ platform: pl, content: post.content, post, conn });
        })
      );

      // Update per-platform status in post_platforms
      for (let i = 0; i < platforms.length; i++) {
        const pl  = platforms[i];
        const res = results[i];
        if (res.status === 'fulfilled') {
          await supabase.from('post_platforms')
            .update({ status: 'published', platform_post_id: res.value?.postId, platform_post_url: res.value?.url, published_at: new Date() })
            .eq('post_id', post.id).eq('platform', pl);
        } else {
          logger.warn('Scheduled publish failed for platform', { postId: post.id, platform: pl, err: res.reason?.message });
          await supabase.from('post_platforms')
            .update({ status: 'failed', error_message: res.reason?.message?.slice(0, 500) })
            .eq('post_id', post.id).eq('platform', pl);
        }
      }

      const anySucceeded = results.some(r => r.status === 'fulfilled');
      if (!anySucceeded) {
        logger.error('All platforms failed for scheduled post', { postId: post.id });
        await supabase.from('posts').update({ status: 'failed' }).eq('id', post.id);
        continue;
      }

      await supabase.from('posts')
        .update({ status: 'published', published_at: new Date() })
        .eq('id', post.id);

    } catch (e) {
      logger.error('Scheduled post failed', { postId: post.id, err: e.message });
      await supabase.from('posts').update({ status: 'failed' }).eq('id', post.id);
    }
  }
};

module.exports = { processScheduledPosts };
