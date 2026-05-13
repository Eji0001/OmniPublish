/**
 * services/schedulerService.js — Processes scheduled posts
 * Runs on a cron every minute from server.js
 */

'use strict';

const { supabase }          = require('../config/database');
const { publishToPlatform } = require('./platformService');
const { sendEmail }         = require('./emailService');
const { logger }            = require('../utils/logger');

const buildPlatformPostPayload = (post, platform) => {
  const platformPost = post.post_platforms?.find(p => p.platform === platform);
  return {
    ...post,
    media_url: platformPost?.custom_media_url || post.media_files?.[0]?.cdn_url || null,
  };
};

const PLATFORM_LABELS = {
  x: 'X (Twitter)',
  youtube: 'YouTube',
  linkedin: 'LinkedIn',
  tiktok: 'TikTok',
  bluesky: 'Bluesky',
  instagram: 'Instagram',
  facebook: 'Facebook',
  telegram: 'Telegram',
  reddit: 'Reddit',
  threads: 'Threads',
  pinterest: 'Pinterest',
  rumble: 'Rumble',
  twitch: 'Twitch',
  snapchat: 'Snapchat',
};

const buildPlatformLabelList = (platforms) => platforms.map(platform => PLATFORM_LABELS[platform] || platform).join(', ');

const escapeHtml = (value) => String(value)
  .replace(/&/g, '&amp;')
  .replace(/</g, '&lt;')
  .replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;')
  .replace(/'/g, '&#39;');

const sendScheduleSuccessNotification = async (post, platformNames) => {
  const { data: user, error } = await supabase
    .from('users')
    .select('email, full_name')
    .eq('id', post.user_id)
    .single();

  if (error || !user?.email) {
    logger.warn('Could not load user for schedule notification', { postId: post.id, userId: post.user_id });
    return;
  }

  const title = post.title || 'your scheduled post';
  const platformList = buildPlatformLabelList(platformNames);
  const subject = `OmniPublish: ${title} published successfully`;
  const greetingName = user.full_name || 'there';
  const text = [
    `Hi ${greetingName},`,
    '',
    `Your scheduled post "${title}" was published successfully to: ${platformList}.`,
    '',
    'Open OmniPublish to review the publish summary.',
  ].join('\n');
  const html = [
    `<p>Hi ${escapeHtml(greetingName)},</p>`,
    `<p>Your scheduled post <strong>${escapeHtml(title)}</strong> was published successfully to: <strong>${escapeHtml(platformList)}</strong>.</p>`,
    '<p>Open OmniPublish to review the publish summary.</p>',
  ].join('');

  try {
    await sendEmail({ to: user.email, subject, text, html });
    logger.info('Scheduled publish notification sent', { postId: post.id, userId: post.user_id, platforms: platformNames });
  } catch (err) {
    logger.warn('Scheduled publish notification failed', { postId: post.id, userId: post.user_id, err: err.message });
  }
};

const processScheduledPosts = async () => {
  const nowIso = new Date().toISOString();

  // Step 1: Find candidate IDs
  const { data: candidates } = await supabase
    .from('posts')
    .select('id')
    .eq('status', 'scheduled')
    .lte('scheduled_at', nowIso)
    .limit(20);

  if (!candidates?.length) return;
  const candidateIds = candidates.map(p => p.id);

  // Step 2: Atomically claim posts — only rows still in 'scheduled' state are returned.
  // Any concurrent scheduler run that already claimed a post won't match eq('status','scheduled').
  const { data: duePosts } = await supabase
    .from('posts')
    .update({ status: 'published', published_at: new Date() })
    .in('id', candidateIds)
    .eq('status', 'scheduled')
    .select('id, user_id, content, title, post_platforms(platform, custom_media_url), media_files(cdn_url)');

  if (!duePosts?.length) return;
  logger.info(`Processing ${duePosts.length} scheduled post(s)`);

  for (const post of duePosts) {
    const platforms = (post.post_platforms || []).map(p => p.platform);
    if (!platforms.length) continue;

    try {
      const { data: validConnections } = await supabase
        .from('platform_connections')
        .select('platform, access_token_enc, platform_user_id, token_expires_at')
        .eq('user_id', post.user_id)
        .in('platform', platforms)
        .eq('is_active', true)
        .or(`token_expires_at.is.null,token_expires_at.gt.${nowIso}`);

      const { data: expiredConnections } = await supabase
        .from('platform_connections')
        .select('platform, token_expires_at')
        .eq('user_id', post.user_id)
        .in('platform', platforms)
        .eq('is_active', true)
        .lte('token_expires_at', nowIso);

      const expiredPlatforms = new Set((expiredConnections || []).map(c => c.platform));
      if (expiredPlatforms.size) {
        logger.warn('Scheduled post has expired platform token(s)', {
          postId: post.id,
          userId: post.user_id,
          platforms: [...expiredPlatforms],
        });

        await Promise.all(
          [...expiredPlatforms].map(platform =>
            supabase.from('post_platforms').update({
              status: 'failed',
              error_message: `Platform token expired. Reconnect ${platform} to resume scheduled publishing.`,
            }).eq('post_id', post.id).eq('platform', platform)
          )
        );
      }

      const publishPlatforms = platforms.filter(platform => !expiredPlatforms.has(platform));
      const connMap = Object.fromEntries((validConnections || []).map(c => [c.platform, c]));

      const results = await Promise.allSettled(
        publishPlatforms.map(pl => {
          const conn = connMap[pl];
          if (!conn) return Promise.reject(Object.assign(new Error(`${pl} not connected`), { platform: pl }));
          return publishToPlatform({ platform: pl, content: post.content, post: buildPlatformPostPayload(post, pl), conn });
        })
      );

      // Update per-platform status in post_platforms
      for (let i = 0; i < publishPlatforms.length; i++) {
        const pl  = publishPlatforms[i];
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
        await supabase.from('posts').update({ status: 'failed', published_at: null }).eq('id', post.id);
        continue;
      }

      const allSucceeded = publishPlatforms.length > 0 && results.every(r => r.status === 'fulfilled');
      if (allSucceeded) {
        await sendScheduleSuccessNotification(post, publishPlatforms);
      }
      // Post was optimistically marked 'published' during the claim step; no further update needed.

    } catch (e) {
      logger.error('Scheduled post failed', { postId: post.id, err: e.message });
      await supabase.from('posts').update({ status: 'failed', published_at: null }).eq('id', post.id);
    }
  }
};

const cleanupRevokedTokens = async () => {
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const { error } = await supabase.from('revoked_tokens').delete().lt('revoked_at', cutoff.toISOString());
  if (error) logger.error('Token cleanup failed', { err: error.message });
  else logger.debug('Revoked token cleanup ran');
};

module.exports = { processScheduledPosts, cleanupRevokedTokens };
