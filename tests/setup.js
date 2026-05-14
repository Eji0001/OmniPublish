'use strict';

// Set all env vars before any module is loaded
process.env.NODE_ENV            = 'test';
process.env.PORT                = '0';
process.env.JWT_ACCESS_SECRET   = 'test-access-secret-at-least-32-chars!!';
process.env.JWT_REFRESH_SECRET  = 'test-refresh-secret-at-least-32-chars!!';
process.env.JWT_EMAIL_CONFIRM_SECRET = 'test-email-confirm-secret-at-least-32-chars!!';
process.env.ENCRYPTION_KEY      = 'a'.repeat(64); // 32 bytes in hex
process.env.SUPABASE_URL        = 'http://localhost:54321';
process.env.SUPABASE_ANON_KEY   = 'test-anon-key';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'test-service-key';
process.env.ALLOWED_ORIGINS     = 'http://localhost:3000';
process.env.GOOGLE_CLIENT_ID    = 'test-google-client-id';
process.env.GOOGLE_CLIENT_SECRET = 'test-google-client-secret';
process.env.REDDIT_CLIENT_ID     = 'test-reddit-client-id';
process.env.REDDIT_CLIENT_SECRET  = 'test-reddit-client-secret';
process.env.PINTEREST_CLIENT_ID  = 'test-pinterest-client-id';
process.env.PINTEREST_CLIENT_SECRET = 'test-pinterest-client-secret';
process.env.LOG_LEVEL           = 'silent';
