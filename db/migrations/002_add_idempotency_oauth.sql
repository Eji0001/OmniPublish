-- ============================================================
-- OmniPublish — Migration 002: Add Idempotency & Error Tracking
-- Engine : PostgreSQL 15+ (Supabase)
-- ============================================================

-- Idempotency tokens table for state-changing operations
CREATE TABLE IF NOT EXISTS idempotency_tokens (
  id                UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  idempotency_key   VARCHAR(36) UNIQUE NOT NULL,
  user_id           UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  response          TEXT        NOT NULL,  -- JSON response body
  created_at        TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  expires_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_idempotency_key ON idempotency_tokens (idempotency_key);
CREATE INDEX IF NOT EXISTS idx_idempotency_user ON idempotency_tokens (user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_tokens (expires_at);

-- OAuth state tracking for CSRF protection
CREATE TABLE IF NOT EXISTS oauth_states (
  id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  state       VARCHAR(128) UNIQUE NOT NULL,
  user_id     UUID,  -- NULL for registration flows
  platform    VARCHAR(50) NOT NULL,
  nonce       VARCHAR(128),
  created_at  TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_state ON oauth_states (state);
CREATE INDEX IF NOT EXISTS idx_oauth_user ON oauth_states (user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_expires ON oauth_states (expires_at);

-- API request tracking for rate limiting and abuse detection
CREATE TABLE IF NOT EXISTS api_requests (
  id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
  ip_address  INET        NOT NULL,
  method      VARCHAR(10) NOT NULL,
  path        VARCHAR(255) NOT NULL,
  status_code INT,
  response_ms INT,
  error_code  VARCHAR(20),
  created_at  TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_user ON api_requests (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_ip ON api_requests (ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_status ON api_requests (status_code) WHERE status_code >= 400;

-- Cleanup job: run DELETE FROM idempotency_tokens WHERE expires_at < NOW();
-- Cleanup job: run DELETE FROM oauth_states WHERE expires_at < NOW();
-- Cleanup job: run DELETE FROM api_requests WHERE created_at < NOW() - INTERVAL '30 days';
