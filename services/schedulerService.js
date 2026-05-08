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

      await Promise.allSettled(
        platforms.map(pl => {
          const conn = connMap[pl];
          if (!conn) return Promise.reject(new Error(`${pl} not connected`));
          return publishToPlatform({ platform: pl, content: post.content, post, conn });
        })
      );

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
