'use strict';

const fs = require('fs');
const path = require('path');

describe('dashboard endpoint wiring', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

  it('references the endpoints used by dashboard click actions', () => {
    const expected = [
      '/api/v1/auth/dev-session',
      '/api/v1/auth/login',
      '/api/v1/auth/register',
      '/api/v1/auth/forgot-password',
      '/api/v1/auth/magic-link',
      '/api/v1/auth/refresh',
      '/api/v1/posts/draft',
      '/api/v1/posts',
      '/api/v1/publish',
      '/api/v1/media/upload',
      '/api/v1/platforms/connect',
      '/api/v1/platforms/',
      '/api/v1/ai/adapt',
      '/api/v1/posts?status=draft&limit=1',
      '/api/v1/posts?page=',
    ];

    expected.forEach(endpoint => {
      expect(html).toContain(endpoint);
    });
  });

  it('keeps the main dashboard inputs mapped to backend storage', () => {
    const expectedStorageSignals = [
      'posts',
      'post_platforms',
      'media_files',
      'scheduled_at',
      'media/upload',
    ];

    expectedStorageSignals.forEach(signal => {
      expect(html).toContain(signal);
    });
  });

  it('refreshes dashboard data after demo auth bootstrap', () => {
    expect(html).toContain('refreshDashboardAfterAuth');
    expect(html).toContain('bootstrapAuthState()');
  });

  it('hides public pages in production and keeps signup routed to auth', () => {
    expect(html).toContain('hideProductionPublicPages');
    expect(html).toContain("if (IS_PRODUCTION && name === 'signup') name = 'auth';");
  });

  it('routes the connections hash into the dedicated connections page', () => {
    expect(html).toContain("hashPage === 'connections'");
    expect(html).toContain("showPage('connections')");
    expect(html).toContain('page-connections');
    expect(html).toContain('connections-next-btn');
    expect(html).toContain('goDashboardFromConnections()');
  });

  it('gives developer hash-based access to connections page in demo mode', () => {
    expect(html).toContain("DEV_PAGES[hashPage] || 'dashboard'");
    expect(html).toContain('showPage(landingPage);');
    expect(html).toContain("localhost:4000/#connections");
  });
});
