'use strict';

const { supabase } = require('../config/database');

const APP_TABLES = [
  'oauth_states',
  'api_requests',
  'audit_logs',
  'password_resets',
  'idempotency_tokens',
  'user_sessions',
  'media_files',
  'platform_connections',
  'posts',
  'users',
];

const AUTH_PAGE_SIZE = 1000;

const isMissingTableError = (error) => {
  const message = String(error?.message || '');
  return error?.code === 'PGRST205' || /Could not find the table 'public\.[^']+' in the schema cache/i.test(message);
};

async function revokeKnownSessions(client = supabase) {
  try {
    const { data, error } = await client.from('user_sessions').select('jti');
    if (error) throw error;

    const jtIs = (data || []).map(row => row.jti).filter(Boolean);
    if (!jtIs.length) return 0;

    const { error: revokeError } = await client.from('revoked_tokens').upsert(
      jtIs.map(jti => ({ jti })),
      { onConflict: 'jti' }
    );
    if (revokeError) throw revokeError;

    return jtIs.length;
  } catch (err) {
    if (err?.code === 'PGRST205' || /Could not find the table 'public\.user_sessions' in the schema cache/i.test(err?.message || '')) {
      return 0;
    }
    throw err;
  }
}

async function deleteAppUserData(client = supabase) {
  const counts = {};
  for (const table of APP_TABLES) {
    let data;
    try {
      const result = await client.from(table).select('id');
      data = result.data;
      if (result.error) throw result.error;
    } catch (err) {
      if (isMissingTableError(err)) {
        counts[table] = 'skipped';
        continue;
      }
      throw err;
    }

    const ids = (data || []).map(row => row.id).filter(Boolean);
    if (ids.length) {
      for (let i = 0; i < ids.length; i += 500) {
        const chunk = ids.slice(i, i + 500);
        const { error: deleteError } = await client.from(table).delete().in('id', chunk);
        if (deleteError) throw deleteError;
      }
    }
    counts[table] = true;
  }
  return counts;
}

async function listAllAuthUsers(authAdmin) {
  const users = [];
  let page = 1;

  while (true) {
    const { data, error } = await authAdmin.listUsers({ page, perPage: AUTH_PAGE_SIZE });
    if (error) throw error;

    const batch = data?.users || [];
    users.push(...batch);
    if (batch.length < AUTH_PAGE_SIZE) break;
    page += 1;
  }

  return users;
}

async function deleteAuthUsers(client = supabase) {
  const authAdmin = client.auth?.admin;
  if (!authAdmin?.listUsers || !authAdmin?.deleteUser) return { deleted: 0, skipped: true };

  const users = await listAllAuthUsers(authAdmin);
  let deleted = 0;

  for (const user of users) {
    const { error } = await authAdmin.deleteUser(user.id);
    if (error) throw error;
    deleted += 1;
  }

  return { deleted, skipped: false };
}

async function resetAllUsers(client = supabase) {
  const revoked = await revokeKnownSessions(client);
  await deleteAppUserData(client);
  const auth = await deleteAuthUsers(client);
  return { revokedSessions: revoked, authDeleted: auth.deleted || 0, authSkipped: !!auth.skipped };
}

module.exports = {
  APP_TABLES,
  revokeKnownSessions,
  deleteAppUserData,
  deleteAuthUsers,
  resetAllUsers,
};
