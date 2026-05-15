'use strict';

const { logger } = require('../utils/logger');

const provider = (process.env.EMAIL_PROVIDER || '').toLowerCase();
const fromEmail = process.env.FROM_EMAIL || 'noreply@localhost';
const fromName  = process.env.FROM_NAME || 'OmniPublish';

async function sendEmail({ to, subject, text, html }) {
  if (!to || !subject) throw new Error('Missing email recipient or subject');

  if (process.env.NODE_ENV === 'test' || !provider) {
    logger.info('Email preview', { to, subject, provider: provider || 'none' });
    return { skipped: true };
  }

  if (provider === 'sendgrid') {
    const key = process.env.SENDGRID_API_KEY;
    if (!key) {
      logger.warn('SENDGRID_API_KEY missing; email not sent', { to, subject });
      return { skipped: true };
    }
    const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }] }],
        from: { email: fromEmail, name: fromName },
        subject,
        content: [
          { type: 'text/plain', value: text || htmlToText(html || '') },
          { type: 'text/html',  value: html || textToHtml(text || '') },
        ],
      }),
    });
    if (!res.ok) throw new Error(`SendGrid error ${res.status}`);
    return { provider: 'sendgrid' };
  }

  if (provider === 'resend') {
    const key = process.env.RESEND_API_KEY;
    if (!key) {
      logger.warn('RESEND_API_KEY missing; email not sent', { to, subject });
      return { skipped: true };
    }
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${key}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: `${fromName} <${fromEmail}>`,
        to,
        subject,
        text: text || htmlToText(html || ''),
        html: html || textToHtml(text || ''),
      }),
    });
    if (!res.ok) throw new Error(`Resend error ${res.status}`);
    return { provider: 'resend' };
  }

  logger.warn('Unsupported email provider', { provider, to, subject });
  return { skipped: true };
}

function textToHtml(text) {
  return `<pre style="font-family:inherit;white-space:pre-wrap">${escapeHtml(text)}</pre>`;
}

function htmlToText(html) {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

module.exports = { sendEmail };
