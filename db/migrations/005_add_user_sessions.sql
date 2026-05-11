-- ============================================================
-- OmniPublish — Migration 005: Track active user sessions
-- Engine : PostgreSQL 15+ (Supabase)
-- ============================================================

CREATE TABLE IF NOT EXISTS user_sessions (
  id           UUID         DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  jti          VARCHAR(64)  UNIQUE NOT NULL,
  issued_at    TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  last_seen_at TIMESTAMPTZ  DEFAULT NOW() NOT NULL,
  revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id ON user_sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_jti ON user_sessions (jti);
CREATE INDEX IF NOT EXISTS idx_user_sessions_revoked ON user_sessions (revoked_at) WHERE revoked_at IS NULL;
