/**
 * services/platformService.js — Platform API publishing handlers
 * Covers: Facebook, X, LinkedIn, Bluesky, Telegram, TikTok, YouTube,
 *         Instagram, Reddit, Threads, Pinterest, Rumble, Twitch, Snapchat
 */

'use strict';

const { decrypt, encrypt }  = require('../utils/encryption');
const { platformApisBreaker } = require('../middleware/circuitBreaker');

const platformRequest = (url, init, timeoutMs = 15000) => platformApisBreaker.execute(async () => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
});

const isExpired = (tokenExpiresAt) => tokenExpiresAt && new Date(tokenExpiresAt) < new Date();

const OAUTH_REFRESH_PROVIDERS = {
  youtube: {
    tokenUrl: 'https://oauth2.googleapis.com/token',
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  },
  x: {
    tokenUrl: 'https://api.twitter.com/2/oauth2/token',
    clientId: process.env.X_CLIENT_ID || process.env.TWITTER_CLIENT_ID,
    clientSecret: process.env.X_CLIENT_SECRET || process.env.TWITTER_CLIENT_SECRET,
  },
  linkedin: {
    tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
    clientId: process.env.LINKEDIN_CLIENT_ID,
    clientSecret: process.env.LINKEDIN_CLIENT_SECRET,
  },
  reddit: {
    tokenUrl: 'https://www.reddit.com/api/v1/access_token',
    clientId: process.env.REDDIT_CLIENT_ID,
    clientSecret: process.env.REDDIT_CLIENT_SECRET,
    useBasicAuthForToken: true,
  },
  tiktok: {
    tokenUrl: 'https://open.tiktokapis.com/v2/oauth/token/',
    clientId: process.env.TIKTOK_CLIENT_KEY,
    clientSecret: process.env.TIKTOK_CLIENT_SECRET,
  },
  pinterest: {
    tokenUrl: 'https://api.pinterest.com/v5/oauth/token',
    clientId: process.env.PINTEREST_CLIENT_ID || process.env.PINTEREST_APP_ID,
    clientSecret: process.env.PINTEREST_CLIENT_SECRET || process.env.PINTEREST_APP_SECRET,
    useBasicAuthForToken: true,
  },
  twitch: {
    tokenUrl: 'https://id.twitch.tv/oauth2/token',
    clientId: process.env.TWITCH_CLIENT_ID,
    clientSecret: process.env.TWITCH_CLIENT_SECRET,
  },
};

const refreshAccessToken = async (platform, conn) => {
  const provider = OAUTH_REFRESH_PROVIDERS[platform];
  if (!provider || !provider.clientId || !provider.clientSecret || !conn.refresh_token_enc) return null;

  const refreshToken = decrypt(conn.refresh_token_enc);
  const tokenParams = new URLSearchParams({
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    refresh_token: refreshToken,
    grant_type: 'refresh_token',
  });

  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (provider.useBasicAuthForToken) {
    headers.Authorization = 'Basic ' + Buffer.from(`${provider.clientId}:${provider.clientSecret}`).toString('base64');
    tokenParams.delete('client_id');
    tokenParams.delete('client_secret');
  }

  const res = await platformRequest(provider.tokenUrl, {
    method: 'POST',
    headers,
    body: tokenParams,
  });

  const data = await res.json();
  if (data.error) {
    throw Object.assign(new Error(data.error_description || data.error), { platform, status: res.status });
  }

  if (!data.access_token) {
    throw Object.assign(new Error(`${platform} token refresh failed`), { platform, status: res.status });
  }

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token || refreshToken,
    expiresAt: data.expires_in ? new Date(Date.now() + data.expires_in * 1000).toISOString() : null,
  };
};

const resolveAccessToken = async ({ platform, conn, persistConnectionTokens }) => {
  const accessToken = decrypt(conn.access_token_enc);
  if (!isExpired(conn.token_expires_at)) return accessToken;

  const refreshed = await refreshAccessToken(platform, conn);
  if (!refreshed) {
    throw Object.assign(new Error(`Platform token expired. Reconnect ${platform} to continue publishing.`), { platform, status: 401 });
  }

  if (typeof persistConnectionTokens === 'function') {
    await persistConnectionTokens(buildTokenUpdate(refreshed, conn));
  }

  return refreshed.accessToken;
};

const buildTokenUpdate = (refreshed, conn) => {
  const updates = {
    access_token_enc: encrypt(refreshed.accessToken),
    token_expires_at: refreshed.expiresAt,
  };

  if (refreshed.refreshToken && (!conn.refresh_token_enc || refreshed.refreshToken !== decrypt(conn.refresh_token_enc))) {
    updates.refresh_token_enc = encrypt(refreshed.refreshToken);
  }

  return updates;
};

const requireMediaUrl = (post, platform) => {
  if (!post.media_url) {
    throw Object.assign(new Error(`${platform} publish requires media attached to the post`), { platform });
  }
  return post.media_url;
};

/**
 * publishToPlatform — dispatches content to the appropriate platform API.
 * @param {Object} params - { platform, content, post, conn }
 * @returns {Object} { postId, url }
 */
const publishToPlatform = async ({ platform, content, post, conn, persistConnectionTokens }) => {
  const accessToken = await resolveAccessToken({ platform, conn, persistConnectionTokens });

  const handlers = {

    /* ── Facebook Graph API ── */
    facebook: async () => {
      const res  = await platformRequest(`https://graph.facebook.com/v19.0/me/feed`, {
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
      const res  = await platformRequest('https://api.twitter.com/2/tweets', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: content }),
      });
      const data = await res.json();
      if (data.errors) throw Object.assign(new Error(data.errors[0]?.message), { platform: 'x' });
      return { postId: data.data.id, url: `https://x.com/i/web/status/${data.data.id}` };
    },

    /* ── LinkedIn UGC Posts API v2 ── */
    linkedin: async () => {
      const res  = await platformRequest('https://api.linkedin.com/v2/ugcPosts', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json', 'X-Restli-Protocol-Version': '2.0.0' },
        body: JSON.stringify({
          author: `urn:li:person:${conn.platform_user_id}`,
          lifecycleState: 'PUBLISHED',
          specificContent: {
            'com.linkedin.ugc.ShareContent': {
              shareCommentary: { text: content },
              shareMediaCategory: 'NONE',
            },
          },
          visibility: { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' },
        }),
      });
      const data = await res.json();
      if (data.status >= 400) throw Object.assign(new Error(data.message || 'LinkedIn post failed'), { platform: 'linkedin' });
      return { postId: data.id, url: `https://www.linkedin.com/feed/update/${data.id}` };
    },

    /* ── Bluesky AT Protocol ── */
    bluesky: async () => {
      const res  = await platformRequest('https://bsky.social/xrpc/com.atproto.repo.createRecord', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo:       conn.platform_user_id,
          collection: 'app.bsky.feed.post',
          record:     { $type: 'app.bsky.feed.post', text: content, createdAt: new Date().toISOString() },
        }),
      });
      const data = await res.json();
      if (data.error) throw Object.assign(new Error(data.message || data.error), { platform: 'bluesky' });
      if (!data.uri)  throw Object.assign(new Error('Bluesky returned no URI'), { platform: 'bluesky' });
      return { postId: data.uri, url: `https://bsky.app/profile/${conn.platform_user_id}` };
    },

    /* ── Telegram Bot API ── */
    telegram: async () => {
      const res  = await platformRequest(`https://api.telegram.org/bot${accessToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: conn.platform_user_id, text: content }),
      });
      const data = await res.json();
      if (!data.ok) throw Object.assign(new Error(data.description), { platform: 'telegram' });
      return { postId: String(data.result.message_id), url: `https://t.me/c/${conn.platform_user_id}` };
    },

    /* ── TikTok Content Posting API ── */
    tiktok: async () => {
      const mediaUrl = requireMediaUrl(post, 'tiktok');
      // TikTok requires a two-step: init upload → publish
      // Using Direct Post API (requires approved app)
      const res  = await platformRequest('https://open.tiktokapis.com/v2/post/publish/content/init/', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json; charset=UTF-8' },
        body: JSON.stringify({
          post_info:    { title: content.slice(0, 150), privacy_level: 'PUBLIC_TO_EVERYONE', disable_duet: false, disable_comment: false, disable_stitch: false },
          source_info:  { source: 'PULL_FROM_URL', video_url: mediaUrl },
        }),
      });
      const data = await res.json();
      if (data.error?.code && data.error.code !== 'ok')
        throw Object.assign(new Error(data.error.message), { platform: 'tiktok' });
      return { postId: data.data?.publish_id || 'pending', url: `https://www.tiktok.com/@${conn.platform_user_id}` };
    },

    /* ── YouTube Data API v3 ── */
    youtube: async () => {
      const res  = await platformRequest('https://www.googleapis.com/youtube/v3/videos?part=snippet,status', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          snippet: { title: post.title || content.slice(0, 100), description: content, tags: [] },
          status:  { privacyStatus: 'public' },
        }),
      });
      const data = await res.json();
      if (data.error) throw Object.assign(new Error(data.error.message), { platform: 'youtube' });
      return { postId: data.id, url: `https://www.youtube.com/watch?v=${data.id}` };
    },

    /* ── Instagram Graph API ── */
    instagram: async () => {
      const mediaUrl = requireMediaUrl(post, 'instagram');
      // Step 1: Create media container
      const containerRes = await platformRequest(
        `https://graph.facebook.com/v19.0/${conn.platform_user_id}/media`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ caption: content, access_token: accessToken, media_type: 'IMAGE', image_url: mediaUrl }),
        }
      );
      const container = await containerRes.json();
      if (container.error) throw Object.assign(new Error(container.error.message), { platform: 'instagram' });

      // Step 2: Publish the container
      const publishRes = await platformRequest(
        `https://graph.facebook.com/v19.0/${conn.platform_user_id}/media_publish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ creation_id: container.id, access_token: accessToken }),
        }
      );
      const published = await publishRes.json();
      if (published.error) throw Object.assign(new Error(published.error.message), { platform: 'instagram' });
      if (!published.id)   throw Object.assign(new Error('Instagram publish returned no ID'), { platform: 'instagram' });
      return { postId: published.id, url: `https://www.instagram.com/p/${published.id}` };
    },

    /* ── Reddit API v1 ── */
    reddit: async () => {
      const res  = await platformRequest('https://oauth.reddit.com/api/submit', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type':  'application/x-www-form-urlencoded',
          'User-Agent':    'OmniPublish/2.0',
        },
        body: new URLSearchParams({
          api_type: 'json', kind: 'self',
          sr:       conn.platform_user_id,   // subreddit name
          title:    post.title || content.slice(0, 300),
          text:     content,
        }),
      });
      const data = await res.json();
      const name = data.json?.data?.name;
      if (!name) throw Object.assign(new Error(data.json?.errors?.[0]?.[1] || 'Reddit post failed'), { platform: 'reddit' });
      return { postId: name, url: `https://www.reddit.com/${name}` };
    },

    /* ── Threads (Meta) API ── */
    threads: async () => {
      // Step 1: Create container
      const containerRes = await platformRequest(
        `https://graph.threads.net/v1.0/${conn.platform_user_id}/threads`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text: content, media_type: 'TEXT', access_token: accessToken }),
        }
      );
      const container = await containerRes.json();
      if (container.error) throw Object.assign(new Error(container.error.message), { platform: 'threads' });

      // Step 2: Publish
      const publishRes = await platformRequest(
        `https://graph.threads.net/v1.0/${conn.platform_user_id}/threads_publish`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ creation_id: container.id, access_token: accessToken }),
        }
      );
      const published = await publishRes.json();
      if (published.error) throw Object.assign(new Error(published.error.message), { platform: 'threads' });
      if (!published.id)   throw Object.assign(new Error('Threads publish returned no ID'), { platform: 'threads' });
      return { postId: published.id, url: `https://www.threads.net/@${conn.platform_user_id}` };
    },

    /* ── Pinterest API v5 ── */
    pinterest: async () => {
      const mediaUrl = post.media_url || null;
      const res  = await platformRequest('https://api.pinterest.com/v5/pins', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          board_id:    conn.platform_user_id,
          title:       post.title || content.slice(0, 100),
          description: content,
          link:        null,
          media_source: mediaUrl
            ? { source_type: 'image_url', url: mediaUrl }
            : { source_type: 'image_base64', content_type: 'image/jpeg', data: '' },
        }),
      });
      const data = await res.json();
      if (data.code) throw Object.assign(new Error(data.message), { platform: 'pinterest' });
      return { postId: data.id, url: `https://www.pinterest.com/pin/${data.id}` };
    },

    /* ── Rumble (no public API) ── */
    rumble: async () => {
      throw Object.assign(
        new Error('Rumble does not have a public publish API. Manual upload required at https://rumble.com/upload'),
        { platform: 'rumble', status: 501 }
      );
    },

    /* ── Twitch (update stream info) ── */
    twitch: async () => {
      const res  = await platformRequest(`https://api.twitch.tv/helix/channels?broadcaster_id=${conn.platform_user_id}`, {
        method: 'PATCH',
        headers: {
          'Authorization':  `Bearer ${accessToken}`,
          'Client-Id':       process.env.TWITCH_CLIENT_ID || '',
          'Content-Type':    'application/json',
        },
        body: JSON.stringify({ title: content.slice(0, 140) }),
      });
      if (!res.ok) throw Object.assign(new Error(`Twitch update failed: ${res.status}`), { platform: 'twitch' });
      return { postId: conn.platform_user_id, url: `https://www.twitch.tv/${conn.platform_user_id}` };
    },

    /* ── Snapchat (requires Snap Creative Kit approval) ── */
    snapchat: async () => {
      throw Object.assign(
        new Error('Snapchat publish requires Snap Creative Kit approval. Contact support to enable this platform.'),
        { platform: 'snapchat', status: 501 }
      );
    },
  };

  const handler = handlers[platform];
  if (!handler) throw Object.assign(new Error(`Platform ${platform} not implemented`), { platform });
  return handler();
};

module.exports = { publishToPlatform };
