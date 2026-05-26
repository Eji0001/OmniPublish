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

  it('lets forced onboarding escape demo-mode dashboard routing', () => {
    expect(html).toContain("(name === 'onboarding' && !opts.force)");
    expect(html).toContain("showPage('onboarding', { force: true })");
  });

  it('shows OAuth permission screen before redirecting to platform authorization', () => {
    expect(html).toContain('renderOAuthPermissionModal');
    expect(html).toContain('renderCredentialsMissingModal');
    expect(html).toContain('authorizeFromPermissionScreen');
    expect(html).toContain('closePermModal');
    expect(html).toContain('PLATFORM_PERMISSIONS');
    expect(html).toContain('PLATFORM_ENV_VARS');
  });

  it('displays platform-specific permission lists for OAuth platforms', () => {
    const oauthPlatforms = ['facebook', 'instagram', 'x', 'linkedin', 'youtube', 'reddit', 'tiktok', 'pinterest', 'twitch', 'snapchat', 'threads'];
    oauthPlatforms.forEach(plat => {
      expect(html).toContain(`${plat}:`);
    });
    expect(html).toContain('perm-overlay');
    expect(html).toContain('perm-auth-btn');
  });

  it('includes Threads in the OAuth platform set with credentials and permissions', () => {
    expect(html).toContain("'threads'");
    expect(html).toContain('THREADS_APP_ID');
    expect(html).toContain('THREADS_APP_SECRET');
    expect(html).toContain('Publish text posts and media threads');
  });

  it('keeps manual token form only for non-OAuth platforms', () => {
    expect(html).toContain('renderManualPlatformModal');
    expect(html).toContain('pm-overlay');
    expect(html).toContain('OAUTH_PLATFORM_IDS.has(platId)');
  });

  it('shows credentials-missing screen instead of manual form for unconfigured OAuth platforms', () => {
    expect(html).toContain('missing credentials|OAuth not supported');
    expect(html).toContain('perm-env-vars');
    expect(html).toContain('FACEBOOK_APP_ID');
    expect(html).toContain('GOOGLE_CLIENT_ID');
    expect(html).toContain('X_CLIENT_ID');
  });
});
