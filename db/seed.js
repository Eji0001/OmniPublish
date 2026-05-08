'use strict';

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const bcrypt           = require('bcryptjs');
const { v4: uuid }     = require('uuid');
const { encrypt }      = require('../utils/encryption');

const CYAN  = '\x1b[36m';
const GREEN = '\x1b[32m';
const RED   = '\x1b[31m';
const DIM   = '\x1b[2m';
const RESET = '\x1b[0m';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } }
);

// ── helpers ────────────────────────────────────────────────
const log  = (msg) => console.log(`  ${GREEN}✓${RESET} ${msg}`);
const info = (msg) => console.log(`  ${DIM}${msg}${RESET}`);

async function insert(table, rows, context) {
  const { data, error } = await supabase.from(table).insert(rows).select();
  if (error) throw Object.assign(error, { context });
  return data;
}

// ── seed data ──────────────────────────────────────────────
async function seed() {
  console.log(`\n${CYAN}OmniPublish — Seeding development data${RESET}\n`);

  // ── 1. Users ────────────────────────────────────────────
  const HASH = await bcrypt.hash('DevPass123!', 12);

  const adminId   = uuid();
  const proUserId = uuid();
  const freeId    = uuid();

  const existingEmails = await supabase
    .from('users')
    .select('email')
    .in('email', ['admin@omnipublish.dev', 'pro@omnipublish.dev', 'free@omnipublish.dev']);

  const seededEmails = new Set((existingEmails.data || []).map(u => u.email));

  const usersToInsert = [
    { id: adminId,   email: 'admin@omnipublish.dev', password_hash: HASH, full_name: 'Admin User',    role: 'admin',      plan: 'enterprise', is_verified: true,  is_active: true },
    { id: proUserId, email: 'pro@omnipublish.dev',   password_hash: HASH, full_name: 'Pro Tester',    role: 'user',       plan: 'pro',        is_verified: true,  is_active: true },
    { id: freeId,    email: 'free@omnipublish.dev',  password_hash: HASH, full_name: 'Free Tester',   role: 'user',       plan: 'free',       is_verified: false, is_active: true },
  ].filter(u => !seededEmails.has(u.email));

  if (usersToInsert.length) {
    await insert('users', usersToInsert, 'users');
    log(`Inserted ${usersToInsert.length} user(s)`);
  } else {
    info('Users already seeded — skipping');
  }

  // ── 2. Platform connections (pro user) ──────────────────
  const fakeToken = encrypt('seed_access_token_placeholder');

  const connections = [
    { user_id: proUserId, platform: 'x',         platform_user_id: 'pro_x_123',        platform_username: '@pro_tester',   access_token_enc: fakeToken, is_active: true },
    { user_id: proUserId, platform: 'linkedin',   platform_user_id: 'pro_li_456',       platform_username: 'Pro Tester',    access_token_enc: fakeToken, is_active: true },
    { user_id: proUserId, platform: 'instagram',  platform_user_id: 'pro_ig_789',       platform_username: 'pro_tester_ig', access_token_enc: fakeToken, is_active: true },
    { user_id: proUserId, platform: 'bluesky',    platform_user_id: 'pro.bsky.social',  platform_username: 'pro.bsky',      access_token_enc: fakeToken, is_active: true },
    { user_id: proUserId, platform: 'telegram',   platform_user_id: '-1001234567890',   platform_username: 'OmniPublishDev',access_token_enc: fakeToken, is_active: true },
  ];

  const { data: existingConns } = await supabase
    .from('platform_connections')
    .select('platform')
    .eq('user_id', proUserId);

  const existingPlatforms = new Set((existingConns || []).map(c => c.platform));
  const connsToInsert = connections.filter(c => !existingPlatforms.has(c.platform));

  if (connsToInsert.length) {
    await insert('platform_connections', connsToInsert, 'platform_connections');
    log(`Inserted ${connsToInsert.length} platform connection(s)`);
  } else {
    info('Platform connections already seeded — skipping');
  }

  // ── 3. Posts ─────────────────────────────────────────────
  const { data: existingPosts } = await supabase
    .from('posts')
    .select('id')
    .eq('user_id', proUserId)
    .limit(1);

  if (!existingPosts?.length) {
    const draftId     = uuid();
    const scheduledId = uuid();
    const publishedId = uuid();

    const posts = [
      {
        id: draftId, user_id: proUserId,
        title: 'Introducing OmniPublish',
        content: 'We just launched OmniPublish — the AI-powered tool that lets you publish to 14 platforms in one click. Here\'s what makes it different...',
        format: 'post', aspect_ratio: '16:9', status: 'draft',
      },
      {
        id: scheduledId, user_id: proUserId,
        title: 'Weekly Tech Roundup',
        content: 'This week in tech: AI breakthroughs, new platform APIs, and the tools that are changing how creators work. Thread incoming 🧵',
        format: 'post', aspect_ratio: '1:1', status: 'scheduled',
        scheduled_at: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
      },
      {
        id: publishedId, user_id: proUserId,
        title: 'Behind the Build',
        content: 'Building a multi-platform publisher taught us a lot about API rate limits, token encryption, and why you should never trust a webhook without a signature.',
        format: 'article', aspect_ratio: '16:9', status: 'published',
        published_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
      },
    ];

    await insert('posts', posts, 'posts');
    log(`Inserted ${posts.length} post(s)`);

    // post_platforms for each post
    const postPlatforms = [
      // draft — pending on x and linkedin
      { post_id: draftId,     platform: 'x',        status: 'pending' },
      { post_id: draftId,     platform: 'linkedin',  status: 'pending' },
      // scheduled — pending on all connected platforms
      { post_id: scheduledId, platform: 'x',        status: 'pending', adapted_content: 'This week in tech 🧵 AI, APIs, and creator tools — a thread.' },
      { post_id: scheduledId, platform: 'linkedin',  status: 'pending', adapted_content: 'Weekly Tech Roundup: AI breakthroughs and the tools reshaping creator workflows.' },
      { post_id: scheduledId, platform: 'instagram', status: 'pending', adapted_content: 'This week in tech 🔥 AI breakthroughs, new APIs, and the tools changing how creators work. Save this! #tech #ai #creators' },
      // published — mix of success and failure
      { post_id: publishedId, platform: 'x',        status: 'published', platform_post_id: 'tweet_abc123', platform_post_url: 'https://x.com/i/web/status/tweet_abc123', published_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() },
      { post_id: publishedId, platform: 'linkedin',  status: 'published', platform_post_id: 'li_post_456',  platform_post_url: 'https://www.linkedin.com/feed/update/li_post_456', published_at: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() },
      { post_id: publishedId, platform: 'instagram', status: 'failed',    error_message: 'Media URL required for Instagram image posts.' },
    ];

    await insert('post_platforms', postPlatforms, 'post_platforms');
    log(`Inserted ${postPlatforms.length} post_platform row(s)`);
  } else {
    info('Posts already seeded — skipping');
  }

  // ── 4. Summary ──────────────────────────────────────────
  console.log(`\n${GREEN}Seed complete.${RESET}`);
  console.log(`\nTest credentials (password: ${CYAN}DevPass123!${RESET}):`);
  console.log(`  admin@omnipublish.dev  — admin / enterprise`);
  console.log(`  pro@omnipublish.dev    — user  / pro`);
  console.log(`  free@omnipublish.dev   — user  / free\n`);
}

seed().catch(err => {
  console.error(`\n${RED}Seed failed${err.context ? ` [${err.context}]` : ''}:${RESET}`, err.message);
  process.exit(1);
});
