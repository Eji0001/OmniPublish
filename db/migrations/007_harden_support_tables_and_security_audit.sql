-- ============================================================
-- OmniPublish — Migration 007: Harden support tables and add security audit RPCs
-- Engine : PostgreSQL 15+ (Supabase)
-- ============================================================

CREATE SCHEMA IF NOT EXISTS maintenance;

ALTER TABLE password_resets ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE idempotency_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_request_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE retry_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  CREATE POLICY audit_logs_own_select ON audit_logs
    FOR SELECT USING (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

REVOKE ALL ON TABLE password_resets FROM anon, authenticated;
REVOKE ALL ON TABLE revoked_tokens FROM anon, authenticated;
REVOKE ALL ON TABLE idempotency_tokens FROM anon, authenticated;
REVOKE ALL ON TABLE oauth_states FROM anon, authenticated;
REVOKE ALL ON TABLE api_requests FROM anon, authenticated;
REVOKE ALL ON TABLE api_request_metrics FROM anon, authenticated;
REVOKE ALL ON TABLE retry_queue FROM anon, authenticated;
REVOKE ALL ON TABLE user_sessions FROM anon, authenticated;

GRANT SELECT, UPDATE ON TABLE users TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE platform_connections TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE posts TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE post_platforms TO authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE media_files TO authenticated;
GRANT SELECT ON TABLE audit_logs TO authenticated;
GRANT SELECT ON TABLE post_publish_summary TO authenticated;

DO $$
BEGIN
  IF to_regprocedure('public.cleanup_expired_resets()') IS NOT NULL THEN
    EXECUTE 'ALTER FUNCTION public.cleanup_expired_resets() SET SCHEMA maintenance';
  END IF;
  IF to_regprocedure('public.cleanup_revoked_tokens()') IS NOT NULL THEN
    EXECUTE 'ALTER FUNCTION public.cleanup_revoked_tokens() SET SCHEMA maintenance';
  END IF;
END $$;

DO $$
BEGIN
  CREATE POLICY users_self ON users
    USING (auth.uid() = id) WITH CHECK (auth.uid() = id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE POLICY pc_own ON platform_connections
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE POLICY posts_own ON posts
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE POLICY pp_own ON post_platforms
    USING (post_id IN (SELECT id FROM posts WHERE user_id = auth.uid()));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE POLICY media_own ON media_files
    USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.get_relation_security_audit(relations text[])
RETURNS TABLE (
  relation text,
  relation_kind text,
  rls_enabled boolean,
  security_invoker boolean,
  policies text[]
) AS $$
  SELECT
    relation_name.relation,
    cls.relkind::text AS relation_kind,
    CASE WHEN cls.relkind IN ('r', 'p') THEN cls.relrowsecurity ELSE false END AS rls_enabled,
    CASE WHEN cls.relkind = 'v' THEN EXISTS (
      SELECT 1
      FROM unnest(COALESCE(cls.reloptions, ARRAY[]::text[])) opt
      WHERE opt = 'security_invoker=true'
    ) ELSE false END AS security_invoker,
    COALESCE(ARRAY_AGG(pol.polname ORDER BY pol.polname) FILTER (WHERE pol.polname IS NOT NULL), ARRAY[]::text[]) AS policies
  FROM unnest(relations) AS relation_name(relation)
  LEFT JOIN pg_class cls
    ON cls.oid = to_regclass(format('public.%I', relation_name.relation))
  LEFT JOIN pg_namespace nsp
    ON nsp.oid = cls.relnamespace AND nsp.nspname = 'public'
  LEFT JOIN pg_policy pol
    ON pol.polrelid = cls.oid
  GROUP BY relation_name.relation, cls.relkind, cls.relrowsecurity, cls.reloptions;
$$ LANGUAGE sql STABLE;

CREATE OR REPLACE FUNCTION public.get_public_security_definer_routines()
RETURNS TABLE (
  signature text,
  routine_name text
) AS $$
  SELECT
    format('%I.%I(%s)', nsp.nspname, proc.proname, pg_get_function_identity_arguments(proc.oid)) AS signature,
    proc.proname AS routine_name
  FROM pg_proc proc
  JOIN pg_namespace nsp ON nsp.oid = proc.pronamespace
  WHERE nsp.nspname = 'public'
    AND proc.prosecdef;
$$ LANGUAGE sql STABLE;

REVOKE ALL ON FUNCTION public.get_relation_security_audit(text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.get_public_security_definer_routines() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.get_relation_security_audit(text[]) TO service_role;
GRANT EXECUTE ON FUNCTION public.get_public_security_definer_routines() TO service_role;

GRANT USAGE ON SCHEMA maintenance TO service_role;
GRANT EXECUTE ON FUNCTION maintenance.cleanup_expired_resets() TO service_role;
GRANT EXECUTE ON FUNCTION maintenance.cleanup_revoked_tokens() TO service_role;
REVOKE ALL ON FUNCTION maintenance.cleanup_expired_resets() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION maintenance.cleanup_revoked_tokens() FROM PUBLIC, anon, authenticated;
