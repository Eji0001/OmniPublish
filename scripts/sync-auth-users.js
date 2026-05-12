'use strict';

const { supabase } = require('../config/database');
const { mirrorAuthUser } = require('../utils/authMirror');
const { logger } = require('../utils/logger');

async function main() {
  const { data: users, error } = await supabase.from('users')
    .select('email, full_name, is_active')
    .eq('is_active', true);

  if (error) throw error;

  const rows = users || [];
  let mirrored = 0;
  let skipped = 0;

  for (const user of rows) {
    const result = await mirrorAuthUser({
      email: user.email,
      fullName: user.full_name || null,
      source: 'sync_auth_users',
    });
    if (result) mirrored += 1;
    else skipped += 1;
  }

  logger.info('Auth user sync complete', { total: rows.length, mirrored, skipped });
  console.log(`Sync complete. mirrored=${mirrored} skipped=${skipped} total=${rows.length}`);
}

main().catch(err => {
  logger.error('Auth user sync failed', { message: err.message, code: err.code });
  console.error(err.message);
  process.exit(1);
});
