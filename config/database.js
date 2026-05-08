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
      const isRetryable = ['PGRST116', '08006', '57P03'].includes(err.code);
      if (!isRetryable || attempt === maxRetries) break;
      const delay = Math.pow(2, attempt) * 100;
      logger.warn(`Retrying [${context}] attempt ${attempt}/${maxRetries} in ${delay}ms`);
      await new Promise(r => setTimeout(r, delay));
    }
  }
  throw lastError;
};

/** Health check — verifies Supabase is reachable */
const dbHealthCheck = async () => {
  try {
    const { error } = await supabase.from('users').select('count').limit(1).single();
    return !error || error.code === 'PGRST116';
  } catch { return false; }
};

module.exports = { supabase, supabasePublic, execute, executeWithRetry, dbHealthCheck };
