-- ============================================================
-- OmniPublish — Migration 001: Initial Schema
-- Engine : PostgreSQL 15+ (Supabase)
-- Idempotent: safe to run on a fresh or existing database
-- ============================================================

-- ── Extensions ────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── ENUM types (DO blocks make these idempotent) ──────────
DO $$ BEGIN CREATE TYPE user_role    AS ENUM ('user', 'moderator', 'admin');           EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE user_plan    AS ENUM ('free', 'starter', 'pro', 'enterprise'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE post_status  AS ENUM ('draft', 'scheduled', 'publishing', 'published', 'failed', 'deleted'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE post_format  AS ENUM ('post', 'video', 'short', 'story', 'article'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE aspect_ratio AS ENUM ('16:9', '9:16', '1:1', '4:5', '2:3');   EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE plat_status  AS ENUM ('pending', 'publishing', 'published', 'failed', 'skipped'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── updated_at trigger function ────────────────────────────
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

-- ── USERS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                    UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  email                 VARCHAR(255) UNIQUE NOT NULL,
  password_hash         VARCHAR(255),
  full_name             VARCHAR(255),
  avatar_url            TEXT,
  role                  user_role    DEFAULT 'user'  NOT NULL,
  plan                  user_plan    DEFAULT 'free'  NOT NULL,
  is_verified           BOOLEAN      DEFAULT FALSE   NOT NULL,
  is_active             BOOLEAN      DEFAULT TRUE    NOT NULL,
  user_type             VARCHAR(32),
  onboarding_completed_at TIMESTAMPTZ,
  last_login_at         TIMESTAMPTZ,
  failed_login_attempts INT          DEFAULT 0       NOT NULL,
  locked_until          TIMESTAMPTZ,
  marketing_consent     BOOLEAN      DEFAULT FALSE,
  marketing_consent_at  TIMESTAMPTZ,
  timezone              VARCHAR(64)  DEFAULT 'UTC',
  created_at            TIMESTAMPTZ  DEFAULT NOW()   NOT NULL,
  updated_at            TIMESTAMPTZ  DEFAULT NOW()   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_users_email  ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_plan   ON users (plan);
CREATE INDEX IF NOT EXISTS idx_users_active ON users (is_active) WHERE is_active = TRUE;

DO $$ BEGIN
  CREATE TRIGGER trg_users_updated BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── PASSWORD RESETS ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS password_resets (
  id          UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id     UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash  VARCHAR(64)  UNIQUE NOT NULL,
  purpose     VARCHAR(32)  NOT NULL CHECK (purpose IN ('password_reset', 'magic_link', 'oauth_exchange')),
  expires_at  TIMESTAMPTZ  NOT NULL,
  used_at     TIMESTAMPTZ,
  created_at  TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pw_reset_token ON password_resets (token_hash);
CREATE INDEX IF NOT EXISTS idx_pw_reset_user  ON password_resets (user_id);
CREATE INDEX IF NOT EXISTS idx_pw_reset_purpose ON password_resets (purpose);

-- ── REVOKED TOKENS (JWT blacklist) ────────────────────────
CREATE TABLE IF NOT EXISTS revoked_tokens (
  id         UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  jti        VARCHAR(64)  UNIQUE NOT NULL,
  user_id    UUID         REFERENCES users(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_jti ON revoked_tokens (jti);

-- ── PLATFORM CONNECTIONS ──────────────────────────────────
CREATE TABLE IF NOT EXISTS platform_connections (
  id                UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id           UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  platform          VARCHAR(50)  NOT NULL,
  platform_user_id  VARCHAR(255),
  platform_username VARCHAR(255),
  access_token_enc  TEXT         NOT NULL,
  refresh_token_enc TEXT,
  token_expires_at  TIMESTAMPTZ,
  scopes            TEXT[]       DEFAULT '{}',
  is_active         BOOLEAN      DEFAULT TRUE NOT NULL,
  connected_at      TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  updated_at        TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  UNIQUE (user_id, platform)
);

CREATE INDEX IF NOT EXISTS idx_pc_user     ON platform_connections (user_id);
CREATE INDEX IF NOT EXISTS idx_pc_platform ON platform_connections (platform);
CREATE INDEX IF NOT EXISTS idx_pc_active   ON platform_connections (user_id, is_active) WHERE is_active = TRUE;

-- ── POSTS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS posts (
  id           UUID          DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id      UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title        VARCHAR(500),
  content      TEXT          NOT NULL CHECK (char_length(content) BETWEEN 1 AND 63206),
  format       post_format   DEFAULT 'post'  NOT NULL,
  aspect_ratio aspect_ratio  DEFAULT '16:9'  NOT NULL,
  status       post_status   DEFAULT 'draft' NOT NULL,
  scheduled_at TIMESTAMPTZ,
  published_at TIMESTAMPTZ,
  created_at   TIMESTAMPTZ   DEFAULT NOW()   NOT NULL,
  updated_at   TIMESTAMPTZ   DEFAULT NOW()   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_posts_user_id   ON posts (user_id);
CREATE INDEX IF NOT EXISTS idx_posts_status    ON posts (status);
CREATE INDEX IF NOT EXISTS idx_posts_scheduled ON posts (scheduled_at) WHERE status = 'scheduled';
CREATE INDEX IF NOT EXISTS idx_posts_created   ON posts (created_at DESC);

DO $$ BEGIN
  CREATE TRIGGER trg_posts_updated BEFORE UPDATE ON posts
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── POST PLATFORMS ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS post_platforms (
  id                UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  post_id           UUID         NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  platform          VARCHAR(50)  NOT NULL,
  adapted_content   TEXT,
  custom_media_url  TEXT,
  status            plat_status  DEFAULT 'pending' NOT NULL,
  platform_post_id  VARCHAR(255),
  platform_post_url TEXT,
  error_message     VARCHAR(500),
  published_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  UNIQUE (post_id, platform)
);

CREATE INDEX IF NOT EXISTS idx_pp_post_id  ON post_platforms (post_id);
CREATE INDEX IF NOT EXISTS idx_pp_platform ON post_platforms (platform);
CREATE INDEX IF NOT EXISTS idx_pp_status   ON post_platforms (status);

-- ── MEDIA FILES ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS media_files (
  id               UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id          UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id          UUID         REFERENCES posts(id) ON DELETE SET NULL,
  filename         VARCHAR(255) NOT NULL,
  original_name    VARCHAR(255),
  mime_type        VARCHAR(100) NOT NULL,
  size_bytes       BIGINT       NOT NULL CHECK (size_bytes > 0),
  storage_path     TEXT         NOT NULL UNIQUE,
  cdn_url          TEXT,
  width            INT,
  height           INT,
  duration_seconds FLOAT,
  created_at       TIMESTAMPTZ  DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_media_user ON media_files (user_id);
CREATE INDEX IF NOT EXISTS idx_media_post ON media_files (post_id);

-- ── AUDIT LOGS ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs (
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

CREATE INDEX IF NOT EXISTS idx_audit_user       ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_time       ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_ip         ON audit_logs (ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs (request_id);

-- ── ROW LEVEL SECURITY ────────────────────────────────────
ALTER TABLE users                ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE posts                ENABLE ROW LEVEL SECURITY;
ALTER TABLE post_platforms       ENABLE ROW LEVEL SECURITY;
ALTER TABLE media_files          ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
  CREATE POLICY users_self ON users
    USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY pc_own ON platform_connections
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY posts_own ON posts
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY pp_own ON post_platforms
    USING (post_id IN (SELECT id FROM posts WHERE user_id = auth.uid()));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE POLICY media_own ON media_files
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ── CLEANUP FUNCTIONS ─────────────────────────────────────
CREATE OR REPLACE FUNCTION cleanup_expired_resets()
RETURNS void AS $$
BEGIN
  DELETE FROM password_resets WHERE expires_at < NOW() AND used_at IS NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION cleanup_revoked_tokens()
RETURNS void AS $$
BEGIN
  DELETE FROM revoked_tokens WHERE revoked_at < NOW() - INTERVAL '8 days';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ── VIEWS ─────────────────────────────────────────────────
CREATE OR REPLACE VIEW post_publish_summary AS
SELECT
  p.id,
  p.user_id,
  p.title,
  p.format,
  p.status,
  p.created_at,
  COUNT(pp.id)                                              AS total_platforms,
  COUNT(pp.id) FILTER (WHERE pp.status = 'published')      AS published_count,
  COUNT(pp.id) FILTER (WHERE pp.status = 'failed')         AS failed_count,
  ARRAY_AGG(pp.platform ORDER BY pp.platform)              AS platforms
FROM posts p
LEFT JOIN post_platforms pp ON pp.post_id = p.id
GROUP BY p.id;
