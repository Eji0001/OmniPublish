-- ============================================================
-- OmniPublish — Migration 008: Fix security audit to exclude event trigger functions
-- rls_auto_enable is a Supabase-managed SECURITY DEFINER function that backs
-- the ensure_rls event trigger. It is intentionally SECURITY DEFINER and cannot
-- be dropped. Exclude functions with a dependent event trigger from the audit.
-- ============================================================

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
    AND proc.prosecdef
    AND NOT EXISTS (
      SELECT 1 FROM pg_event_trigger evt
      WHERE evt.evtfoid = proc.oid
    );
$$ LANGUAGE sql STABLE;
