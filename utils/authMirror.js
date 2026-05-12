'use strict';

const crypto = require('crypto');
const { supabase } = require('../config/database');
const { logger } = require('./logger');

const isDuplicateAuthUserError = (error) => {
  const message = String(error?.message || '').toLowerCase();
  return Boolean(
    error?.status === 422
    || error?.code === 'user_already_exists'
    || /already exists|already registered|duplicate/i.test(message)
  );
};

const buildAuthUserPayload = ({ email, password, fullName, source }) => ({
  email,
  password: password || crypto.randomBytes(24).toString('hex'),
  email_confirm: true,
  user_metadata: {
    full_name: fullName || null,
    source: source || 'omnipublish',
  },
});

const mirrorAuthUser = async ({ email, password, fullName, source }) => {
  const authAdmin = supabase.auth?.admin;
  if (!authAdmin?.createUser) return null;

  const payload = buildAuthUserPayload({ email, password, fullName, source });
  const { data, error } = await authAdmin.createUser(payload);

  if (error) {
    if (isDuplicateAuthUserError(error)) {
      logger.debug('Auth user already exists; skipping mirror', { email, source: source || 'omnipublish' });
      return null;
    }

    logger.warn('Failed to mirror auth user', {
      email,
      source: source || 'omnipublish',
      message: error.message,
      code: error.code,
    });
    return null;
  }

  return data?.user || null;
};

module.exports = { mirrorAuthUser };
