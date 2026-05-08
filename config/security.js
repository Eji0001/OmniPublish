/**
 * config/security.js
 * Centralised security configuration and custom header middleware.
 */

'use strict';

const securityHeaders = (req, res, next) => {
  res.setHeader('Permissions-Policy', [
    'accelerometer=()', 'ambient-light-sensor=()', 'autoplay=()', 'battery=()',
    'camera=()', 'display-capture=()', 'geolocation=()', 'gyroscope=()',
    'magnetometer=()', 'microphone=()', 'payment=()', 'usb=()', 'xr-spatial-tracking=()',
  ].join(', '));

  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }

  const requestId = req.headers['x-request-id'] ||
    `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  res.removeHeader('Server');
  res.removeHeader('X-Powered-By');
  next();
};

const JWT_CONFIG = {
  accessSecret:     process.env.JWT_ACCESS_SECRET  || 'dev-access-secret-change-in-prod',
  refreshSecret:    process.env.JWT_REFRESH_SECRET || 'dev-refresh-secret-change-in-prod',
  accessExpiresIn:  '15m',
  refreshExpiresIn: '7d',
  algorithm:        'HS256',
  issuer:           'omnipublish-api',
  audience:         'omnipublish-client',
};

const BCRYPT_ROUNDS = 12;

const LOCKOUT_POLICY = {
  maxFailedAttempts: 5,
  lockDurationMs:    15 * 60 * 1000,
};

const PASSWORD_POLICY = {
  minLength:        12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber:    true,
  requireSpecial:   true,
  specialChars:     '!@#$%^&*()_+-=[]{}|;:,.<>?',
};

const validatePassword = (password) => {
  const errors = [];
  if (password.length < PASSWORD_POLICY.minLength)
    errors.push(`Minimum ${PASSWORD_POLICY.minLength} characters required`);
  if (PASSWORD_POLICY.requireUppercase && !/[A-Z]/.test(password))
    errors.push('Must contain at least one uppercase letter');
  if (PASSWORD_POLICY.requireLowercase && !/[a-z]/.test(password))
    errors.push('Must contain at least one lowercase letter');
  if (PASSWORD_POLICY.requireNumber && !/\d/.test(password))
    errors.push('Must contain at least one number');
  if (PASSWORD_POLICY.requireSpecial &&
      !new RegExp(`[${PASSWORD_POLICY.specialChars.replace(/[[\]\\^]/g, '\\$&')}]`).test(password))
    errors.push('Must contain at least one special character');
  return errors;
};

const ALLOWED_MEDIA_TYPES = {
  image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  video: ['video/mp4', 'video/quicktime', 'video/webm', 'video/avi'],
};

const MAX_FILE_SIZE = {
  image: 25  * 1024 * 1024,
  video: 512 * 1024 * 1024,
};

module.exports = {
  securityHeaders, JWT_CONFIG, BCRYPT_ROUNDS, LOCKOUT_POLICY,
  PASSWORD_POLICY, validatePassword, ALLOWED_MEDIA_TYPES, MAX_FILE_SIZE,
};
