'use strict';

const jwt = require('jsonwebtoken');
const { JWT_CONFIG } = require('../config/security');
const { logger } = require('../utils/logger');
const { sendEmail } = require('./emailService');

const APP_URL = process.env.APP_URL || 'http://localhost:4000';

function makeLink(token) {
  return `${APP_URL}/?confirm=${token}`;
}

async function issueConfirmationLink(user, options = {}) {
  const { subject = 'Confirm your OmniPublish email', headline = 'Confirm your email', cta = 'Confirm email' } = options;
  if (!user?.id || !user?.email) throw new Error('User email is required');

  const token = jwt.sign(
    { purpose: 'email_confirm', userId: user.id, email: user.email },
    JWT_CONFIG.accessSecret,
    { expiresIn: '1h', issuer: JWT_CONFIG.issuer, audience: JWT_CONFIG.audience, algorithm: JWT_CONFIG.algorithm }
  );

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
