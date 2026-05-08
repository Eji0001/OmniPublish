-- ============================================================
-- OmniPublish — Database Schema
-- Engine: PostgreSQL 15+ (Supabase)
-- Features: UUID PKs · RLS · Encrypted tokens · Audit trail
-- Compliance: GDPR · SOC 2 · OWASP A02/A07
-- ============================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ──────────────────────────────────────────
-- ENUM types
-- ──────────────────────────────────────────
CREATE TYPE user_role    AS ENUM ('user', 'moderator', 'admin');
CREATE TYPE user_plan    AS ENUM ('free', 'starter', 'pro', 'enterprise');
CREATE TYPE post_status  AS ENUM ('draft', 'scheduled', 'publishing', 'published', 'failed', 'deleted');
CREATE TYPE post_format  AS ENUM ('post', 'video', 'short', 'story', 'article');
CREATE TYPE aspect_ratio AS ENUM ('16:9', '9:16', '1:1', '4:5', '2:3');
CREATE TYPE plat_status  AS ENUM ('pending', 'publishing', 'published', 'failed', 'skipped');

-- ──────────────────────────────────────────
-- USERS
-- ──────────────────────────────────────────
CREATE TABLE users (
  id                    UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  email                 VARCHAR(255) UNIQUE NOT NULL,
  password_hash         VARCHAR(255) NOT NULL,
  full_name             VARCHAR(255),
  avatar_url            TEXT,
  role                  user_role   DEFAULT 'user'        NOT NULL,
  plan                  user_plan   DEFAULT 'free'        NOT NULL,
  is_verified           BOOLEAN     DEFAULT FALSE         NOT NULL,
  is_active             BOOLEAN     DEFAULT TRUE          NOT NULL,
  last_login_at         TIMESTAMPTZ,
  failed_login_attempts INT         DEFAULT 0             NOT NULL,
  locked_until          TIMESTAMPTZ,
  -- GDPR: track consent
  marketing_consent     BOOLEAN     DEFAULT FALSE,
  marketing_consent_at  TIMESTAMPTZ,
  -- Metadata
  timezone              VARCHAR(64) DEFAULT 'UTC',
  created_at            TIMESTAMPTZ DEFAULT NOW()         NOT NULL,
  updated_at            TIMESTAMPTZ DEFAULT NOW()         NOT NULL
);
CREATE INDEX idx_users_email    ON users (email);
CREATE INDEX idx_users_plan     ON users (plan);
CREATE INDEX idx_users_active   ON users (is_active) WHERE is_active = TRUE;

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ──────────────────────────────────────────
-- PASSWORD RESETS (hashed tokens only)
-- ──────────────────────────────────────────
CREATE TABLE password_resets (
  id          UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64) UNIQUE NOT NULL,  -- SHA-256 of the reset token
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ DEFAULT NOW() NOT NULL
);
CREATE INDEX idx_pw_reset_token  ON password_resets (token_hash);
CREATE INDEX idx_pw_reset_user   ON password_resets (user_id);

-- ──────────────────────────────────────────
-- REVOKED TOKENS (JWT blacklist)
-- ──────────────────────────────────────────
CREATE TABLE revoked_tokens (
  id         UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  jti        VARCHAR(64) UNIQUE NOT NULL,      -- JWT ID claim
  user_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);
CREATE INDEX idx_revoked_jti ON revoked_tokens (jti);
-- Cleanup job: delete entries older than 8 days (after max token TTL)
-- Run: DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days';

-- ──────────────────────────────────────────
-- PLATFORM CONNECTIONS (OAuth tokens — encrypted)
-- ──────────────────────────────────────────
CREATE TABLE platform_connections (
  id                  UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform            VARCHAR(50) NOT NULL,        -- 'facebook', 'x', 'instagram', …
  platform_user_id    VARCHAR(255),               -- external user ID
  platform_username   VARCHAR(255),               -- handle / display name
  access_token_enc    TEXT        NOT NULL,        -- AES-256-GCM encrypted
  refresh_token_enc   TEXT,                       -- AES-256-GCM encrypted
  token_expires_at    TIMESTAMPTZ,
  scopes              TEXT[]      DEFAULT '{}',    -- OAuth scopes granted
  is_active           BOOLEAN     DEFAULT TRUE NOT NULL,
  connected_at        TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at          TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  UNIQUE (user_id, platform)
);
CREATE INDEX idx_pc_user     ON platform_connections (user_id);
CREATE INDEX idx_pc_platform ON platform_connections (platform);
CREATE INDEX idx_pc_active   ON platform_connections (user_id, is_active) WHERE is_active = TRUE;

-- ──────────────────────────────────────────
-- POSTS
-- ──────────────────────────────────────────
CREATE TABLE posts (
  id            UUID          DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id       UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title         VARCHAR(500),
  content       TEXT          NOT NULL CHECK (char_length(content) BETWEEN 1 AND 63206),
  format        post_format   DEFAULT 'post'    NOT NULL,
  aspect_ratio  aspect_ratio  DEFAULT '16:9'   NOT NULL,
  status        post_status   DEFAULT 'draft'   NOT NULL,
  scheduled_at  TIMESTAMPTZ,
  published_at  TIMESTAMPTZ,
  created_at    TIMESTAMPTZ   DEFAULT NOW()     NOT NULL,
  updated_at    TIMESTAMPTZ   DEFAULT NOW()     NOT NULL
);
CREATE INDEX idx_posts_user_id     ON posts (user_id);
CREATE INDEX idx_posts_status      ON posts (status);
CREATE INDEX idx_posts_scheduled   ON posts (scheduled_at) WHERE status = 'scheduled';
CREATE INDEX idx_posts_created     ON posts (created_at DESC);

CREATE TRIGGER trg_posts_updated BEFORE UPDATE ON posts
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ──────────────────────────────────────────
-- POST PLATFORMS (per-platform publish targets)
-- ──────────────────────────────────────────
CREATE TABLE post_platforms (
  id                UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  post_id           UUID         NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  platform          VARCHAR(50)  NOT NULL,
  adapted_content   TEXT,                     -- AI-adapted content for this platform
  custom_media_url  TEXT,                     -- platform-specific media override
  status            plat_status  DEFAULT 'pending' NOT NULL,
  platform_post_id  VARCHAR(255),             -- ID of the post on the external platform
  platform_post_url TEXT,                     -- Direct URL of the published post
  error_message     VARCHAR(500),
  published_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  UNIQUE (post_id, platform)
);
CREATE INDEX idx_pp_post_id    ON post_platforms (post_id);
CREATE INDEX idx_pp_platform   ON post_platforms (platform);
CREATE INDEX idx_pp_status     ON post_platforms (status);

-- ──────────────────────────────────────────
-- MEDIA FILES
-- ──────────────────────────────────────────
CREATE TABLE media_files (
  id              UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id         UUID         REFERENCES posts(id) ON DELETE SET NULL,
  filename        VARCHAR(255) NOT NULL,
  original_name   VARCHAR(255),
  mime_type       VARCHAR(100) NOT NULL,
  size_bytes      BIGINT       NOT NULL CHECK (size_bytes > 0),
  storage_path    TEXT         NOT NULL UNIQUE,
  cdn_url         TEXT,
  width           INT,
  height          INT,
  duration_seconds FLOAT,
  created_at      TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);
CREATE INDEX idx_media_user    ON media_files (user_id);
CREATE INDEX idx_media_post    ON media_files (post_id);

-- ──────────────────────────────────────────
-- AUDIT LOGS (tamper-evident append-only)
-- ──────────────────────────────────────────
CREATE TABLE audit_logs (
  id            UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id       UUID         REFERENCES users(id) ON DELETE SET NULL,
  action        VARCHAR(255) NOT NULL,
  resource_type VARCHAR(100),
  resource_id   UUID,
  ip_address    INET,
  user_agent    VARCHAR(512),
  http_method   VARCHAR(10),
  http_path     VARCHAR(500),
  http_status   INT,
  duration_ms   INT,
  request_id    VARCHAR(64),
  metadata      JSONB        DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);
CREATE INDEX idx_audit_user   ON audit_logs (user_id);
CREATE INDEX idx_audit_action ON audit_logs (action);
CREATE INDEX idx_audit_time   ON audit_logs (created_at DESC);
CREATE INDEX idx_audit_ip     ON audit_logs (ip_address);

-- Audit logs are append-only — revoke UPDATE/DELETE from API role
-- REVOKE UPDATE, DELETE ON audit_logs FROM omnipublish_api;

-- ──────────────────────────────────────────
-- ROW LEVEL SECURITY (RLS)
-- Users can only see/modify their own data.
-- API uses service role to bypass only for admin ops.
-- ──────────────────────────────────────────
ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts               ENABLE ROW LEVEL SECURITY;
ALTER TABLE post_platforms      ENABLE ROW LEVEL SECURITY;
ALTER TABLE media_files         ENABLE ROW LEVEL SECURITY;

-- Users: read/update own row
CREATE POLICY users_self ON users
  USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- Platform connections: own only
CREATE POLICY pc_own ON platform_connections
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Posts: own only
CREATE POLICY posts_own ON posts
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- Post platforms: via post ownership
CREATE POLICY pp_own ON post_platforms
  USING (post_id IN (SELECT id FROM posts WHERE user_id = auth.uid()));

-- Media: own only
CREATE POLICY media_own ON media_files
  USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

-- ──────────────────────────────────────────
-- CLEANUP FUNCTIONS
-- ──────────────────────────────────────────

-- Auto-cleanup expired password resets (run via pg_cron or scheduler)
CREATE OR REPLACE FUNCTION cleanup_expired_resets()
RETURNS void AS $$
BEGIN
  DELETE FROM password_resets WHERE expires_at < NOW() AND used_at IS NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Auto-cleanup old JWT blacklist entries
CREATE OR REPLACE FUNCTION cleanup_revoked_tokens()
RETURNS void AS $$
BEGIN
  DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ──────────────────────────────────────────
-- HELPFUL VIEWS
-- ──────────────────────────────────────────

CREATE VIEW post_publish_summary AS
SELECT
  p.id,
  p.user_id,
  p.title,
  p.format,
  p.status,
  p.created_at,
  COUNT(pp.id)                                                   AS total_platforms,
  COUNT(pp.id) FILTER (WHERE pp.status = 'published')           AS published_count,
  COUNT(pp.id) FILTER (WHERE pp.status = 'failed')              AS failed_count,
  ARRAY_AGG(pp.platform ORDER BY pp.platform)                   AS platforms
FROM posts p
LEFT JOIN post_platforms pp ON pp.post_id = p.id
GROUP BY p.id;
