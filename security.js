/**
 * config/security.js
 * Centralised security configuration and custom header middleware.
 * Applied globally after Helmet to add permissions policy and
 * additional response hardening.
 */

'use strict';

/**
 * securityHeaders middleware
 * Adds Permissions-Policy, Cache-Control on API routes, and
 * removes headers that leak server information.
 */
const securityHeaders = (req, res, next) => {
  // Restrict browser feature access
  res.setHeader('Permissions-Policy', [
    'accelerometer=()',
    'ambient-light-sensor=()',
    'autoplay=()',
    'battery=()',
    'camera=()',
    'display-capture=()',
    'geolocation=()',
    'gyroscope=()',
    'magnetometer=()',
    'microphone=()',
    'payment=()',
    'usb=()',
    'xr-spatial-tracking=()',
  ].join(', '));

  // Prevent response caching for API endpoints
  if (req.path.startsWith('/api/')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }

  // Unique request tracing ID (passed from client or generated)
  const requestId = req.headers['x-request-id'] || `req_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  // Remove server fingerprinting
  res.removeHeader('Server');
  res.removeHeader('X-Powered-By');

  next();
};

/**
 * JWT configuration
 * Centralised token settings used by auth middleware and routes.
 */
const JWT_CONFIG = {
  accessSecret:  process.env.JWT_ACCESS_SECRET,
  refreshSecret: process.env.JWT_REFRESH_SECRET,
  accessExpiresIn:  '15m',   // short-lived access token
  refreshExpiresIn: '7d',    // longer-lived refresh token
  algorithm:     'HS256',
  issuer:        'omnipublish-api',
  audience:      'omnipublish-client',
};

/**
 * Bcrypt rounds — cost factor for password hashing.
 * 12 rounds ≈ 300ms on modern hardware. OWASP recommends ≥10.
 */
const BCRYPT_ROUNDS = 12;

/**
 * Account lockout policy — OWASP A07 (Identification & Auth Failures)
 */
const LOCKOUT_POLICY = {
  maxFailedAttempts: 5,
  lockDurationMs:    15 * 60 * 1000,   // 15 minutes
};

/**
 * Password strength requirements
 */
const PASSWORD_POLICY = {
  minLength:       12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumber:    true,
  requireSpecial:   true,
  specialChars:    '!@#$%^&*()_+-=[]{}|;:,.<>?',
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
  if (PASSWORD_POLICY.requireSpecial && !new RegExp(`[${PASSWORD_POLICY.specialChars.replace(/[\[\]\\^]/g, '\\$&')}]`).test(password))
    errors.push('Must contain at least one special character');
  return errors;
};

/**
 * Allowed file MIME types for media upload
 */
const ALLOWED_MEDIA_TYPES = {
  image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp'],
  video: ['video/mp4', 'video/quicktime', 'video/webm', 'video/avi'],
};

const MAX_FILE_SIZE = {
  image: 25  * 1024 * 1024,    // 25 MB
  video: 512 * 1024 * 1024,    // 512 MB
};

module.exports = {
  securityHeaders,
  JWT_CONFIG,
  BCRYPT_ROUNDS,
  LOCKOUT_POLICY,
  PASSWORD_POLICY,
  validatePassword,
  ALLOWED_MEDIA_TYPES,
  MAX_FILE_SIZE,
};
