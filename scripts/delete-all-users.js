'use strict';

require('dotenv').config();

const { resetAllUsers } = require('../utils/userReset');
const { logger } = require('../utils/logger');

async function main() {
  if (process.env.CONFIRM_DELETE_ALL_USERS !== 'YES') {
    throw new Error('Set CONFIRM_DELETE_ALL_USERS=YES to delete all user accounts');
  }

  const summary = await resetAllUsers();
  logger.warn('All user accounts deleted for onboarding reset', summary);
  console.log(`Deleted all users. revokedSessions=${summary.revokedSessions} authDeleted=${summary.authDeleted}`);
}

main().catch(err => {
  logger.error('Delete-all-users failed', { message: err.message, code: err.code });
  console.error(err.message);
  process.exit(1);
});
