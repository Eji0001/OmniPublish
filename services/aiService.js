/**
 * services/aiService.js — Anthropic AI content adaptation
 * SECURE: Called only from the backend. API key never exposed to browser.
 */

'use strict';

const Anthropic  = require('@anthropic-ai/sdk');
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

/**
 * aiAdaptContent — adapts content for each selected platform via Claude.
 * @param {Object} params - { content, platforms, format, ratio, userId }
 * @returns {Object} adapted — { platformId: adaptedText }
 */
const aiAdaptContent = async ({ content, platforms, format, ratio, userId }) => {
  const specs = platforms.map(pid => {
    const p = PLATFORM_PROFILES[pid] || { limit: 1000, tone: 'appropriate for platform' };
    return `- ${pid}: max ${p.limit} chars, tone: ${p.tone}`;
  }).join('\n');

  const systemPrompt = `You are an elite social media strategist. Adapt the given content for each platform. Format context: ${format || 'post'}, aspect ratio: ${ratio || '16:9'}. Return ONLY a raw JSON object — no markdown, no code fences, no explanation. Keys are exact platform IDs, values are adapted content strings. Strictly respect character limits.`;
  const userPrompt   = `Platforms:\n${specs}\n\nOriginal content:\n"${content}"\n\nReturn JSON: {"facebook":"...","x":"...",...}`;

  const start = Date.now();
  let adapted = {};

  try {
    const message = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514', max_tokens: 2500,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
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

module.exports = { aiAdaptContent, PLATFORM_PROFILES };
