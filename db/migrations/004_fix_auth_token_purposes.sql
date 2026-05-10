-- ============================================================
-- OmniPublish — Migration 004: Fix auth token purposes and user schema
-- Engine : PostgreSQL 15+ (Supabase)
-- ============================================================

ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS user_type VARCHAR(32);
ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarding_completed_at TIMESTAMPTZ;

ALTER TABLE password_resets ADD COLUMN IF NOT EXISTS purpose VARCHAR(32);

UPDATE password_resets
SET purpose = 'password_reset'
WHERE purpose IS NULL;

ALTER TABLE password_resets
  ALTER COLUMN purpose SET NOT NULL;

DO $$ BEGIN
  ALTER TABLE password_resets
    ADD CONSTRAINT password_resets_purpose_check
    CHECK (purpose IN ('password_reset', 'magic_link', 'oauth_exchange'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_pw_reset_purpose ON password_resets (purpose);
