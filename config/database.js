/**
 * config/database.js
 * Supabase client with connection validation, typed query helpers, and retry logic.
 */

'use strict';

const { createClient } = require('@supabase/supabase-js');
const { logger }       = require('../utils/logger');

const SUPABASE_URL     = process.env.SUPABASE_URL;
const SUPABASE_ANON    = process.env.SUPABASE_ANON_KEY;
const SUPABASE_SERVICE = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE) {
  logger.error('Missing Supabase env vars — check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY');
  if (process.env.NODE_ENV === 'production') process.exit(1);
}

/** Public client — uses anon key, RLS enforced */
const supabasePublic = createClient(SUPABASE_URL || 'http://localhost', SUPABASE_ANON || 'anon', {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  global: { headers: { 'x-application-name': 'omnipublish-api' } },
});

/** Service-role client — bypasses RLS, for server-only operations */
const supabase = createClient(SUPABASE_URL || 'http://localhost', SUPABASE_SERVICE || 'service', {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  global: { headers: { 'x-application-name': 'omnipublish-api-service' } },
});

const CORE_RELATIONS = [
  'users',
  'password_resets',
  'revoked_tokens',
  'platform_connections',
  'posts',
  'post_platforms',
  'media_files',
  'audit_logs',
];

const SUPPORT_RELATIONS = [
  'idempotency_tokens',
  'oauth_states',
  'api_requests',
  'retry_queue',
  'user_sessions',
  'post_publish_summary',
];

const REQUIRED_RELATIONS = [...CORE_RELATIONS, ...SUPPORT_RELATIONS];

/**
 * execute — wraps a Supabase query with error handling and logging.
 */
const execute = async (queryFn, context = 'db.query') => {
  const start = Date.now();
  const { data, error } = await queryFn();
  const ms = Date.now() - start;
  if (error) {
    logger.error(`DB error [${context}]`, { message: error.message, code: error.code, ms });
    const e = new Error(error.message || 'Database error');
    e.code   = error.code;
    e.status = 500;
    throw e;
  }
  if (ms > 2000) logger.warn(`Slow query [${context}]`, { ms });
  return data;
};

/**
 * executeWithRetry — retries transient DB errors up to maxRetries times.
 */
const executeWithRetry = async (queryFn, context, maxRetries = 3) => {
  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try { return await execute(queryFn, context); }
    catch (err) {
      lastError = err;
      const isRetryable = ['08006', '57P03'].includes(err.code);
      if (!isRetryable || attempt === maxRetries) break;
      const delay = Math.pow(2, attempt) * 100;
      logger.warn(`Retrying [${context}] attempt ${attempt}/${maxRetries} in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastError;
};

const probeRelation = async (relation) => {
  try {
    const { error } = await supabase.from(relation).select('id').limit(1);
    return { relation, ok: !error, error: error || null };
  } catch (err) {
    return { relation, ok: false, error: err };
  }
};

/** Health check — verifies Supabase is reachable and MVP relations exist */
const dbSchemaHealthCheck = async () => {
  const checks = await Promise.all(REQUIRED_RELATIONS.map(probeRelation));
  const missingRelations = checks.filter(result => !result.ok).map(result => result.relation);
  const missingCoreRelations = checks.filter(result => CORE_RELATIONS.includes(result.relation) && !result.ok).map(result => result.relation);
  const missingSupportRelations = checks.filter(result => SUPPORT_RELATIONS.includes(result.relation) && !result.ok).map(result => result.relation);
  return {
    ok: missingCoreRelations.length === 0,
    missingRelations,
    missingCoreRelations,
    missingSupportRelations,
    checks,
  };
};

const dbHealthCheck = async () => {
  try {
    const schema = await dbSchemaHealthCheck();
    return schema.ok;
  } catch {
    return false;
  }
};

module.exports = { supabase, supabasePublic, execute, executeWithRetry, dbHealthCheck, dbSchemaHealthCheck, REQUIRED_RELATIONS, CORE_RELATIONS, SUPPORT_RELATIONS };
