/**
 * config/database.js
 * Supabase client with connection validation, typed query helpers, and retry logic.
 */

'use strict';

const { createClient } = require('@supabase/supabase-js');
const ws               = require('ws');
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
  realtime: { transport: ws },
});

/**
 * createUserScopedClient — accepts a JWT token or a raw userId string.
 * Decodes the sub claim when a JWT is passed so that callers in auth.js
 * (which pass the raw Bearer token) get the same auto-scoped wrapper as
 * callers that pass payload.sub directly.  Delegates to userScopedDb so
 * there is exactly one enforcement point for the user_id guard.
 */
const createUserScopedClient = (tokenOrUserId) => {
  if (!tokenOrUserId) throw Object.assign(new Error('createUserScopedClient requires a token or userId'), { status: 500 });
  let userId = tokenOrUserId;
  if (typeof tokenOrUserId === 'string' && tokenOrUserId.split('.').length === 3) {
    try {
      const decoded = JSON.parse(Buffer.from(tokenOrUserId.split('.')[1], 'base64url').toString('utf8'));
      if (decoded?.sub) userId = decoded.sub;
    } catch { /* fall through — use tokenOrUserId as-is */ }
  }
  return userScopedDb(userId);
};

/** Service-role client — bypasses RLS, for server-only operations */
const supabase = createClient(SUPABASE_URL || 'http://localhost', SUPABASE_SERVICE || 'service', {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  global: { headers: { 'x-application-name': 'omnipublish-api-service' } },
  realtime: { transport: ws },
});

/**
 * Tables that have a direct user_id column and should be auto-scoped.
 * post_platforms is excluded — ownership is enforced via posts.user_id.
 */
const _USER_OWNED_TABLES = new Set(['posts', 'media_files', 'platform_connections']);

/**
 * userScopedDb — wraps the service client so that all DML on user-owned tables
 * automatically includes a user_id guard. Eliminates the entire class of IDOR
 * bugs where a developer forgets to scope a query.
 *
 * select  → appends .eq('user_id', userId) before the caller chains more filters
 * insert  → injects user_id into the payload (array or object)
 * update  → appends .eq('user_id', userId) so stray updates can't touch other users
 * delete  → appends .eq('user_id', userId) so stray deletes can't touch other users
 * upsert  → caller is responsible for including user_id (conflict resolution needs it)
 *
 * Tables NOT in _USER_OWNED_TABLES are passed through unmodified (post_platforms,
 * users, revoked_tokens, audit_logs, etc. follow their own ownership model).
 */
const userScopedDb = (userId) => {
  if (!userId) throw Object.assign(new Error('userScopedDb requires a userId'), { status: 500 });
  return {
    from(table) {
      const base = supabase.from(table);
      if (!_USER_OWNED_TABLES.has(table)) return base;
      return {
        select: (...args)    => base.select(...args).eq('user_id', userId),
        insert: (data)       => base.insert(
          Array.isArray(data)
            ? data.map(r => ({ user_id: userId, ...r }))
            : { user_id: userId, ...data }
        ),
        update: (data)       => base.update(data).eq('user_id', userId),
        delete: ()           => base.delete().eq('user_id', userId),
        upsert: (data, opts) => base.upsert(data, opts),
      };
    },
    get storage() { return supabase.storage; },
  };
};

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
  'api_request_metrics',
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

const fetchSecurityAudit = async () => {
  if (typeof supabase.rpc !== 'function') return null;

  const [relationAudit, definerAudit] = await Promise.all([
    supabase.rpc('get_relation_security_audit', { relations: REQUIRED_RELATIONS }),
    supabase.rpc('get_public_security_definer_routines'),
  ]);

  if (relationAudit?.error && definerAudit?.error) return null;

  return {
    relations: relationAudit?.data || [],
    securityDefinerRoutines: definerAudit?.data || [],
  };
};

const normalizeAuditRows = (rows = []) => rows.reduce((acc, row) => {
  if (row?.relation) acc[row.relation] = row;
  return acc;
}, {});

const REQUIRED_POLICIES = {
  users: ['users_self'],
  platform_connections: ['pc_own'],
  posts: ['posts_own'],
  post_platforms: ['pp_own'],
  media_files: ['media_own'],
  audit_logs: ['audit_logs_own_select'],
};

const SUPPORT_RLS_RELATIONS = [
  'password_resets',
  'revoked_tokens',
  'idempotency_tokens',
  'oauth_states',
  'api_requests',
  'api_request_metrics',
  'retry_queue',
  'user_sessions',
  'audit_logs',
];

/** Health check — verifies Supabase is reachable and MVP relations exist */
const dbSchemaHealthCheck = async () => {
  const checks = await Promise.all(REQUIRED_RELATIONS.map(probeRelation));
  const missingRelations = checks.filter(result => !result.ok).map(result => result.relation);
  const missingCoreRelations = checks.filter(result => CORE_RELATIONS.includes(result.relation) && !result.ok).map(result => result.relation);
  const missingSupportRelations = checks.filter(result => SUPPORT_RELATIONS.includes(result.relation) && !result.ok).map(result => result.relation);

  const securityAudit = await fetchSecurityAudit();
  const relationAudit = normalizeAuditRows(securityAudit?.relations);
  const securityDefinerRoutines = securityAudit?.securityDefinerRoutines || [];

  const rlsMissing = [];
  const policyMissing = [];
  const viewSecurityMissing = [];

  if (securityAudit) {
    for (const relation of SUPPORT_RLS_RELATIONS) {
      const row = relationAudit[relation];
      if (!row || row.relation_kind === 'v') continue;
      if (!row.rls_enabled) rlsMissing.push(relation);
    }

    for (const [relation, policies] of Object.entries(REQUIRED_POLICIES)) {
      const row = relationAudit[relation];
      if (!row) continue;
      const currentPolicies = Array.isArray(row?.policies) ? row.policies : [];
      const missingPolicies = policies.filter(policy => !currentPolicies.includes(policy));
      if (missingPolicies.length) policyMissing.push({ relation, missingPolicies });
    }

    const summaryView = relationAudit.post_publish_summary;
    if (summaryView && summaryView.relation_kind === 'v' && !summaryView.security_invoker) {
      viewSecurityMissing.push('post_publish_summary');
    }
  }

  const unsafeRoutines = securityDefinerRoutines.map(routine => routine.routine_name || routine.signature || routine);

  return {
    ok: missingCoreRelations.length === 0
      && rlsMissing.length === 0
      && policyMissing.length === 0
      && viewSecurityMissing.length === 0
      && unsafeRoutines.length === 0,
    missingRelations,
    missingCoreRelations,
    missingSupportRelations,
    rlsMissing,
    policyMissing,
    viewSecurityMissing,
    unsafeRoutines,
    securityAudit,
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

module.exports = { supabase, supabasePublic, createUserScopedClient, userScopedDb, execute, executeWithRetry, dbHealthCheck, dbSchemaHealthCheck, REQUIRED_RELATIONS, CORE_RELATIONS, SUPPORT_RELATIONS };
