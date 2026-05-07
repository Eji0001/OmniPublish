/**
 * services/aiService.js     — Anthropic AI content adaptation
 * services/platformService.js — Platform API publishing stubs
 * services/schedulerService.js — Scheduled post processor
 * utils/encryption.js        — AES-256-GCM token encryption
 * utils/logger.js            — Winston structured logger
 */

'use strict';

/* ══════════════════════════════════════════
   AI SERVICE — Anthropic content adaptation
══════════════════════════════════════════ */
// services/aiService.js
const Anthropic = require('@anthropic-ai/sdk');
const { logger } = require('../utils/logger');

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const PLATFORM_PROFILES = {
  facebook:  { limit: 63206, tone: 'conversational and engaging, use emojis, tag people' },
  tiktok:    { limit: 2200,  tone: 'trendy, Gen-Z energy, heavy hashtags, use #fyp #viral' },
  linkedin:  { limit: 3000,  tone: 'professional, insightful, no slang, thought leadership style' },
  youtube:   { limit: 5000,  tone: 'SEO-optimised description, include keywords, chapters if long' },
  instagram: { limit: 2200,  tone: 'visual storytelling, lifestyle tone, 5–30 hashtags at end' },
  twitch:    { limit: 500,   tone: 'gaming/streaming community language, call to action' },
  x:         { limit: 280,   tone: 'punchy, witty, viral hook, optional hashtag, thread-worthy' },
  telegram:  { limit: 4096,  tone: 'informative, can be longer, channel-appropriate' },
  reddit:    { limit: 40000, tone: 'authentic, no marketing speak, subreddit-appropriate, value-first' },
  threads:   { limit: 500,   tone: 'casual and conversational, Instagram-adjacent' },
  pinterest: { limit: 500,   tone: 'descriptive visual keywords, SEO-focused, aspirational' },
  rumble:    { limit: 2000,  tone: 'direct, community-focused, video description style' },
  bluesky:   { limit: 300,   tone: 'tech-savvy, decentralised ethos, short and smart' },
  snapchat:  { limit: 250,   tone: 'casual, ephemeral, FOMO-inducing, youth-oriented' },
};

const aiAdaptContent = async ({ content, platforms, format, ratio, userId }) => {
  const specs = platforms.map(pid => {
    const p = PLATFORM_PROFILES[pid] || { limit: 1000, tone: 'appropriate for platform' };
    return `- ${pid}: max ${p.limit} chars, tone: ${p.tone}`;
  }).join('\n');

  const systemPrompt = `You are an elite social media strategist. Adapt the given content for each platform. Format context: ${format || 'post'}, aspect ratio: ${ratio || '16:9'}. Return ONLY a raw JSON object — no markdown, no code fences, no explanation. Keys are exact platform IDs, values are the adapted content strings. Strictly respect character limits.`;

  const userPrompt = `Platforms:\n${specs}\n\nOriginal content:\n"${content}"\n\nReturn JSON: {"facebook":"...","x":"...",...}`;

  const start = Date.now();
  let adapted = {};

  try {
    const message = await anthropic.messages.create({
      model:      'claude-sonnet-4-20250514',
      max_tokens: 2500,
      system:     systemPrompt,
      messages:   [{ role: 'user', content: userPrompt }],
    });

    const raw = message.content.find(b => b.type === 'text')?.text || '{}';
    adapted = JSON.parse(raw.replace(/```json|```/g, '').trim());
    logger.info('AI adapt completed', { userId, platforms: platforms.length, ms: Date.now() - start });
  } catch (err) {
    logger.error('AI adapt failed', { userId, err: err.message });
    // Graceful fallback: truncate to limit
    platforms.forEach(pid => {
      const lim = PLATFORM_PROFILES[pid]?.limit || 1000;
      adapted[pid] = content.length > lim ? content.slice(0, lim - 4) + '...' : content;
    });
  }

  return adapted;
};

/* ══════════════════════════════════════════
   PLATFORM SERVICE — API publishing stubs
   Replace stubs with real SDK calls per platform
══════════════════════════════════════════ */
// services/platformService.js
const { decrypt } = require('./encryptionHelper');

const publishToPlatform = async ({ platform, content, post, conn }) => {
  const accessToken = decrypt(conn.access_token_enc);

  const handlers = {
    /* ── Facebook Graph API ── */
    facebook: async () => {
      const res = await fetch(`https://graph.facebook.com/v19.0/me/feed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: content, access_token: accessToken }),
      });
      const data = await res.json();
      if (data.error) throw Object.assign(new Error(data.error.message), { platform: 'facebook' });
      return { postId: data.id, url: `https://www.facebook.com/${data.id}` };
    },

    /* ── X (Twitter) API v2 ── */
    x: async () => {
      const res = await fetch('https://api.twitter.com/2/tweets', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: content }),
      });
      const data = await res.json();
      if (data.errors) throw Object.assign(new Error(data.errors[0]?.message), { platform: 'x' });
      return { postId: data.data.id, url: `https://x.com/i/web/status/${data.data.id}` };
    },

    /* ── LinkedIn API ── */
    linkedin: async () => {
      const res = await fetch('https://api.linkedin.com/v2/shares', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          owner: `urn:li:person:${conn.platform_user_id}`,
          text: { text: content },
          distribution: { linkedInDistributionTarget: { visibleToGuest: true } },
        }),
      });
      const data = await res.json();
      return { postId: data.id, url: `https://www.linkedin.com/feed/update/${data.id}` };
    },

    /* ── Bluesky AT Protocol ── */
    bluesky: async () => {
      const res = await fetch('https://bsky.social/xrpc/com.atproto.repo.createRecord', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo:       conn.platform_user_id,
          collection: 'app.bsky.feed.post',
          record: { $type: 'app.bsky.feed.post', text: content, createdAt: new Date().toISOString() },
        }),
      });
      const data = await res.json();
      return { postId: data.uri, url: `https://bsky.app/profile/${conn.platform_user_id}` };
    },

    /* ── Telegram Bot API ── */
    telegram: async () => {
      const res = await fetch(`https://api.telegram.org/bot${accessToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: conn.platform_user_id, text: content, parse_mode: 'HTML' }),
      });
      const data = await res.json();
      if (!data.ok) throw Object.assign(new Error(data.description), { platform: 'telegram' });
      return { postId: String(data.result.message_id), url: `https://t.me/c/${conn.platform_user_id}` };
    },

    // Add: tiktok, youtube, instagram, reddit, threads, pinterest, rumble, twitch, snapchat
    // Each uses their respective official SDK / API
  };

  const handler = handlers[platform];
  if (!handler) throw Object.assign(new Error(`Platform ${platform} not implemented`), { platform });
  return handler();
};

/* ══════════════════════════════════════════
   SCHEDULER SERVICE
══════════════════════════════════════════ */
// services/schedulerService.js
const { supabase: db } = require('../config/database');

const processScheduledPosts = async () => {
  const { data: duePosts } = await db
    .from('posts')
    .select('id, user_id, content, post_platforms(platform)')
    .eq('status', 'scheduled')
    .lte('scheduled_at', new Date().toISOString())
    .limit(20);

  if (!duePosts?.length) return;
  logger.info(`Processing ${duePosts.length} scheduled post(s)`);

  for (const post of duePosts) {
    const platforms = (post.post_platforms || []).map(p => p.platform);
    if (!platforms.length) continue;

    // Re-use publish logic
    try {
      const { data: connections } = await db
        .from('platform_connections')
        .select('platform, access_token_enc, platform_user_id')
        .eq('user_id', post.user_id)
        .in('platform', platforms)
        .eq('is_active', true);

      const connMap = Object.fromEntries((connections || []).map(c => [c.platform, c]));
      await Promise.allSettled(platforms.map(pl => publishToPlatform({ platform: pl, content: post.content, post, conn: connMap[pl] })));
      await db.from('posts').update({ status: 'published', published_at: new Date() }).eq('id', post.id);
    } catch (e) {
      logger.error('Scheduled post failed', { postId: post.id, err: e.message });
      await db.from('posts').update({ status: 'failed' }).eq('id', post.id);
    }
  }
};

/* ══════════════════════════════════════════
   ENCRYPTION UTILITY — AES-256-GCM
   Used to encrypt OAuth tokens at rest.
   Covers: GDPR Art. 32 · SOC 2 CC6.7
══════════════════════════════════════════ */
// utils/encryption.js
const crypto = require('crypto');

const ALGO   = 'aes-256-gcm';
const KEY    = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');   // 32-byte hex key
const IV_LEN = 16;
const TAG_LEN = 16;

if (process.env.NODE_ENV === 'production' && KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be a 32-byte (64-char hex) string');
}

const encrypt = (plaintext) => {
  const iv     = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  // Format: iv(hex):tag(hex):ciphertext(hex)
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
};

const decrypt = (ciphertext) => {
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Invalid ciphertext format');
  const iv      = Buffer.from(ivHex,  'hex');
  const tag     = Buffer.from(tagHex, 'hex');
  const enc     = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
};

// Expose as module for platform service
const encryptionHelper = { encrypt, decrypt };

/* ══════════════════════════════════════════
   WINSTON LOGGER — structured JSON logging
   Covers: SOC 2 CC7.2 (audit trail)
══════════════════════════════════════════ */
// utils/logger.js
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

const { combine, timestamp, json, errors, colorize, simple } = winston.format;

const isProd = process.env.NODE_ENV === 'production';

const transports = [
  // Console — colourised in dev, JSON in prod
  new winston.transports.Console({
    format: isProd ? combine(timestamp(), json()) : combine(colorize(), simple()),
    silent: process.env.NODE_ENV === 'test',
  }),
];

if (isProd) {
  // Rotating file: daily, 14-day retention, gzip
  transports.push(
    new DailyRotateFile({
      filename:     'logs/app-%DATE%.log',
      datePattern:  'YYYY-MM-DD',
      maxFiles:     '14d',
      zippedArchive: true,
      format:        combine(timestamp(), errors({ stack: true }), json()),
    }),
    new DailyRotateFile({
      filename:     'logs/error-%DATE%.log',
      datePattern:  'YYYY-MM-DD',
      level:        'error',
      maxFiles:     '30d',
      zippedArchive: true,
      format:        combine(timestamp(), errors({ stack: true }), json()),
    })
  );
}

const logger = winston.createLogger({
  level:      process.env.LOG_LEVEL || (isProd ? 'info' : 'debug'),
  format:     combine(timestamp(), errors({ stack: true }), json()),
  transports,
  // Prevent logger from throwing on unexpected errors
  exitOnError: false,
});

const httpLogStream = { write: (msg) => logger.http(msg.trim()) };

// Re-export for cross-service use
module.exports = {
  aiAdaptContent,
  publishToPlatform,
  processScheduledPosts,
  encrypt,
  decrypt,
  encryptionHelper,
  logger,
  httpLogStream,
};
