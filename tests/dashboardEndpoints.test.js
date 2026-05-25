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
});
