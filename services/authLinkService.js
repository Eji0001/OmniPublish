'use strict';

const crypto = require('crypto');
const { supabase } = require('../config/database');
const { logger } = require('../utils/logger');
const { sendEmail } = require('./emailService');

const APP_URL = process.env.APP_URL || 'http://localhost:4000';
const MAGIC_LINK_PURPOSE = 'magic_link';

function makeLink(token) {
  return `${APP_URL}/?magic=${token}`;
}

async function issueConfirmationLink(user, options = {}) {
  const { subject = 'Confirm your OmniPublish email', headline = 'Confirm your email', cta = 'Confirm email' } = options;
  if (!user?.id || !user?.email) throw new Error('User email is required');

  if (process.env.NODE_ENV === 'test') {
    logger.debug('Confirmation email skipped in test', { userId: user.id, email: user.email });
    return { skipped: true, link: makeLink('test-token') };
  }

  await supabase.from('password_resets')
    .delete()
    .eq('user_id', user.id)
    .eq('purpose', MAGIC_LINK_PURPOSE)
    .is('used_at', null);

  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

  const { error } = await supabase.from('password_resets').insert({
    id: crypto.randomUUID(),
    user_id: user.id,
    token_hash: tokenHash,
    purpose: MAGIC_LINK_PURPOSE,
    expires_at: expiresAt,
  });
  if (error) throw new Error(error.message || 'Failed to create verification link');

  const link = makeLink(token);
  const firstName = user.full_name?.split(' ')?.[0] || 'there';
  const text = [
    `Hi ${firstName},`,
    '',
    `${headline}. Click the link below to verify your email and continue to onboarding:`,
    link,
    '',
    'If you did not request this, you can ignore this email.',
  ].join('\n');
  const html = [
    `<p>Hi ${escapeHtml(firstName)},</p>`,
    `<p>${escapeHtml(headline)}. Click the link below to verify your email and continue to onboarding.</p>`,
    `<p><a href="${link}">${escapeHtml(cta)}</a></p>`,
    `<p style="color:#666;font-size:12px">If you did not request this, you can ignore this email.</p>`,
  ].join('');

  await sendEmail({
    to: user.email,
    subject,
    text,
    html,
  });

  logger.info('Confirmation email queued', { userId: user.id, email: user.email });
  return { link, token };
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { issueConfirmationLink };
