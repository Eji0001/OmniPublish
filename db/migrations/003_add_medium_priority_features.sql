-- ============================================================
-- OmniPublish — Migration 003: Add Medium-Priority Features
-- Engine : PostgreSQL 15+ (Supabase)
-- Features: Retry queue, GDPR, graceful shutdown support
-- ============================================================

-- Retry queue for failed scheduled operations
CREATE TABLE IF NOT EXISTS retry_queue (
  id              UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  operation_type  VARCHAR(50) NOT NULL,
  payload         JSONB       NOT NULL,
  attempt         INT         DEFAULT 0 NOT NULL,
  max_retries     INT         DEFAULT 5 NOT NULL,
  status          VARCHAR(20) DEFAULT 'pending' NOT NULL,  -- pending, completed, failed
  last_error      TEXT,
  failure_reason  TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  next_retry_at   TIMESTAMPTZ NOT NULL,
  completed_at    TIMESTAMPTZ,
  failed_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_retry_queue_status ON retry_queue (status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_retry_queue_created ON retry_queue (created_at DESC);

-- Extended users table for GDPR
ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_requested_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deletion_scheduled_for TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_users_deletion ON users (deletion_scheduled_for) WHERE deletion_scheduled_for IS NOT NULL;

-- Audit logs for activity tracking
CREATE TABLE IF NOT EXISTS audit_logs (
  id              UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  action          VARCHAR(50) NOT NULL,
  resource_type   VARCHAR(50),
  resource_id     VARCHAR(255),
  changes         JSONB,
  ip_address      INET,
  user_agent      TEXT,
  status          INT,
  error_message   TEXT,
  created_at      TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource_type, resource_id);

-- API request metrics for monitoring
CREATE TABLE IF NOT EXISTS api_request_metrics (
  id              UUID        DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id         UUID REFERENCES users(id) ON DELETE SET NULL,
  method          VARCHAR(10) NOT NULL,
  path            VARCHAR(255) NOT NULL,
  status_code     INT         NOT NULL,
  response_ms     INT,
  request_size    INT,
  response_size   INT,
  error_code      VARCHAR(20),
  ip_address      INET,
  created_at      TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_api_metrics_user ON api_request_metrics (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_metrics_path ON api_request_metrics (path, status_code, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_metrics_time ON api_request_metrics (created_at DESC);

-- Schedule automatic cleanup
-- DELETE FROM idempotency_tokens WHERE expires_at < NOW() - INTERVAL '1 day';
-- DELETE FROM oauth_states WHERE expires_at < NOW();
-- DELETE FROM api_request_metrics WHERE created_at < NOW() - INTERVAL '30 days';
-- DELETE FROM retry_queue WHERE status = 'completed' AND completed_at < NOW() - INTERVAL '7 days';
-- DELETE FROM retry_queue WHERE status = 'failed' AND failed_at < NOW() - INTERVAL '30 days';
