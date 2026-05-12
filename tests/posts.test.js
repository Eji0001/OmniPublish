'use strict';

const request = require('supertest');
const { mockChain } = require('./helpers/db');
const { TEST_USER, generateAccessToken } = require('./helpers/auth');

// ── Module mocks ───────────────────────────────────────────

jest.mock('../config/database', () => ({
  supabase: { from: jest.fn(), storage: { from: jest.fn() } },
  supabasePublic: { from: jest.fn() },
  dbHealthCheck: jest.fn().mockResolvedValue(true),
  execute: jest.fn(),
  executeWithRetry: jest.fn(),
}));

jest.mock('../middleware/rateLimit', () => {
  const pass = (_req, _res, next) => next();
  return {
    globalRateLimiter: pass, authRateLimiter: pass, authSlowDown: pass,
    aiRateLimiter: pass, mediaRateLimiter: pass, publishRateLimiter: pass,
  };
});

jest.mock('../middleware/csrf', () => ({
  verifyCSRF:        (_req, _res, next) => next(),
  generateCSRFToken: () => 'test-csrf-token',
}));

jest.mock('../services/aiService', () => ({
  aiAdaptContent: jest.fn().mockResolvedValue({ x: 'adapted for x', linkedin: 'adapted for linkedin' }),
  PLATFORM_PROFILES: {},
}));

const app = require('../server');
const { supabase } = require('../config/database');

// ── Fixtures ───────────────────────────────────────────────

const POST_ID   = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
const MOCK_POST = {
  id: POST_ID, user_id: TEST_USER.id,
  title: 'Test Post', content: 'Hello world',
  format: 'post', aspect_ratio: '16:9',
  status: 'draft', created_at: new Date().toISOString(),
  post_platforms: [], media_files: [],
};

function authHeader() {
  const { token } = generateAccessToken(TEST_USER);
  return { Authorization: `Bearer ${token}` };
}

beforeEach(() => jest.clearAllMocks());

// ── GET /api/v1/posts ──────────────────────────────────────

describe('GET /api/v1/posts', () => {
  it('200 — returns paginated posts for authenticated user', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))     // revoked_tokens check
      .mockReturnValueOnce(mockChain(                                   // posts query (direct await)
        { data: null, error: null },
        { data: [MOCK_POST], error: null, count: 1 }
      ));

    const res = await request(app)
      .get('/api/v1/posts')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('posts');
    expect(res.body).toHaveProperty('total');
  });

  it('200 — defaults malformed pagination parameters', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [MOCK_POST], error: null, count: 1 }));

    const res = await request(app)
      .get('/api/v1/posts?page=abc&limit=xyz')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.page).toBe(1);
    expect(res.body.limit).toBe(20);
  });

  it('401 — rejects unauthenticated request', async () => {
    const res = await request(app).get('/api/v1/posts');
    expect(res.status).toBe(401);
  });
});

// ── GET /api/v1/posts/stats/overview ──────────────────────

describe('GET /api/v1/posts/stats/overview', () => {
  it('200 — returns status counts and platform stats', async () => {
    const posts = [
      { id: 'p1', status: 'published' },
      { id: 'p2', status: 'draft' },
    ];
    const platforms = [
      { platform: 'x', status: 'published' },
      { platform: 'linkedin', status: 'failed' },
    ];

    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))   // revoked_tokens check
      .mockReturnValueOnce(mockChain(                                 // posts select (direct await)
        { data: null, error: null },
        { data: posts, error: null }
      ))
      .mockReturnValueOnce(mockChain(                                 // post_platforms select (direct await)
        { data: null, error: null },
        { data: platforms, error: null }
      ));

    const res = await request(app)
      .get('/api/v1/posts/stats/overview')
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('statusCounts');
    expect(res.body).toHaveProperty('platformStats');
    expect(res.body.statusCounts.published).toBe(1);
    expect(res.body.statusCounts.draft).toBe(1);
  });
});

// ── GET /api/v1/posts/:id ──────────────────────────────────

describe('GET /api/v1/posts/:id', () => {
  it('200 — returns post owned by user', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))        // revoked_tokens
      .mockReturnValueOnce(mockChain({ data: MOCK_POST, error: null }));  // post select

    const res = await request(app)
      .get(`/api/v1/posts/${POST_ID}`)
      .set(authHeader());

    expect(res.status).toBe(200);
    expect(res.body.post.id).toBe(POST_ID);
  });

  it('404 — returns 404 for post belonging to another user', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))       // revoked_tokens
      .mockReturnValueOnce(mockChain({ data: null, error: { message: 'not found' } })); // no result

    const res = await request(app)
      .get(`/api/v1/posts/${POST_ID}`)
      .set(authHeader());

    expect(res.status).toBe(404);
  });
});

// ── POST /api/v1/posts ─────────────────────────────────────

describe('POST /api/v1/posts', () => {
  it('201 — creates post with platform targets', async () => {
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))        // revoked_tokens
      .mockReturnValueOnce(mockChain({ data: MOCK_POST, error: null }))   // insert post
      .mockReturnValue(mockChain({ data: null, error: null }));           // insert post_platforms

    const res = await request(app)
      .post('/api/v1/posts')
      .set(authHeader())
      .send({ content: 'Hello world', platforms: ['x', 'linkedin'] });

    expect(res.status).toBe(201);
    expect(res.body.post).toHaveProperty('id');
  });

  it('422 — rejects missing content', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .post('/api/v1/posts')
      .set(authHeader())
      .send({ platforms: ['x'] }); // no content

    expect(res.status).toBe(422);
  });

  it('422 — rejects empty platforms array', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .post('/api/v1/posts')
      .set(authHeader())
      .send({ content: 'Hello', platforms: [] });

    expect(res.status).toBe(422);
  });
});

// ── PATCH /api/v1/posts/:id ────────────────────────────────

describe('PATCH /api/v1/posts/:id', () => {
  it('200 — updates allowed fields', async () => {
    const updated = { ...MOCK_POST, title: 'New Title' };
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))         // revoked_tokens
      .mockReturnValueOnce(mockChain({ data: updated, error: null }));     // update

    const res = await request(app)
      .patch(`/api/v1/posts/${POST_ID}`)
      .set(authHeader())
      .send({ title: 'New Title' });

    expect(res.status).toBe(200);
    expect(res.body.post.title).toBe('New Title');
  });

  it('422 — rejects status=published (cannot manually force publish)', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .patch(`/api/v1/posts/${POST_ID}`)
      .set(authHeader())
      .send({ status: 'published' });

    expect(res.status).toBe(422);
  });

  it('422 — rejects status=scheduled without scheduled_at', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .patch(`/api/v1/posts/${POST_ID}`)
      .set(authHeader())
      .send({ status: 'scheduled' });

    expect(res.status).toBe(422);
    expect(res.body.errors?.[0]?.field).toBe('scheduled_at');
  });

  it('422 — rejects unknown fields (strict schema)', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .patch(`/api/v1/posts/${POST_ID}`)
      .set(authHeader())
      .send({ user_id: 'hijacked' });

    expect(res.status).toBe(422);
  });
});

// ── DELETE /api/v1/posts/:id ───────────────────────────────

describe('DELETE /api/v1/posts/:id', () => {
  it('204 — deletes post owned by user', async () => {
    const remove = jest.fn().mockResolvedValue({ error: null });
    supabase.storage.from.mockReturnValueOnce({ remove });
    supabase.from
      .mockReturnValueOnce(mockChain({ data: null, error: null }))  // revoked_tokens
      .mockReturnValueOnce(mockChain({ data: null, error: null }, { data: [{ storage_path: 'posts/p1.webp' }], error: null }))
      .mockReturnValue(mockChain({ data: null, error: null }));      // delete

    const res = await request(app)
      .delete(`/api/v1/posts/${POST_ID}`)
      .set(authHeader());

    expect(res.status).toBe(204);
    expect(supabase.storage.from).toHaveBeenCalledWith('media');
    expect(remove).toHaveBeenCalledWith(['posts/p1.webp']);
  });
});

// ── POST /api/v1/posts/adapt ───────────────────────────────

describe('POST /api/v1/posts/adapt', () => {
  it('200 — returns AI-adapted content per platform', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .post('/api/v1/posts/adapt')
      .set(authHeader())
      .send({ content: 'Original content', platforms: ['x', 'linkedin'] });

    expect(res.status).toBe(200);
    expect(res.body.adapted).toHaveProperty('x');
    expect(res.body.adapted).toHaveProperty('linkedin');
  });

  it('422 — rejects missing platforms', async () => {
    supabase.from.mockReturnValueOnce(mockChain({ data: null, error: null })); // revoked_tokens

    const res = await request(app)
      .post('/api/v1/posts/adapt')
      .set(authHeader())
      .send({ content: 'Original content' }); // no platforms

    expect(res.status).toBe(422);
  });
});
