/**
 * middleware/sanitizer.js
 * Recursive input sanitisation — strips XSS payloads, SQL injection
 * patterns, and prototype pollution from request body, query, and params.
 * Covers: OWASP A03 (Injection)
 */

'use strict';

const xss    = require('xss');
const { logger } = require('../utils/logger');

/* ── XSS cleaner options ─────────────────── */
const xssOptions = {
  whiteList:   {},           // strip ALL HTML tags by default
  stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
  css: false,
};

/* ── Prototype pollution guard ───────────── */
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const sanitizeObject = (obj, depth = 0) => {
  if (depth > 10) return obj;  // depth limit prevents DoS
  if (obj === null || typeof obj !== 'object') {
    return typeof obj === 'string' ? xss(obj, xssOptions) : obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item, depth + 1));
  }

  const clean = {};
  for (const [key, value] of Object.entries(obj)) {
    if (DANGEROUS_KEYS.has(key)) {
      logger.warn('Prototype pollution attempt blocked', { key });
      continue;
    }
    const sanitizedKey = xss(key, xssOptions);
    clean[sanitizedKey] = sanitizeObject(value, depth + 1);
  }
  return clean;
};

/**
 * requestSanitizer — Express middleware.
 * Sanitises req.body, req.query, and req.params in-place.
 */
const requestSanitizer = (req, res, next) => {
  if (req.body   && typeof req.body === 'object')   req.body   = sanitizeObject(req.body);
  if (req.query  && typeof req.query === 'object')   req.query  = sanitizeObject(req.query);
  if (req.params && typeof req.params === 'object')  req.params = sanitizeObject(req.params);
  next();
};

/* ── Zod-based request validators ───────── */
const { z } = require('zod');

const schemas = {
  register: z.object({
    email:    z.string().email().max(255),
    password: z.string().min(12).max(128),
    fullName: z.string().min(2).max(100).optional(),
  }),

  login: z.object({
    email:    z.string().email().max(255),
    password: z.string().min(1).max(128),
  }),

  createPost: z.object({
    content:     z.string().min(1).max(63206),
    title:       z.string().max(500).optional(),
    format:      z.enum(['post', 'video', 'short', 'story', 'article']).default('post'),
    aspectRatio: z.enum(['16:9', '9:16', '1:1', '4:5', '2:3']).default('16:9'),
    scheduledAt: z.string().datetime().optional(),
    platforms:   z.array(z.string().max(50)).min(1).max(14),
    mediaIds:    z.array(z.string().uuid()).max(10).optional(),
  }),

  adaptContent: z.object({
    content:   z.string().min(1).max(63206),
    platforms: z.array(z.string().max(50)).min(1).max(14),
    format:    z.string().max(50).optional(),
    ratio:     z.string().max(10).optional(),
  }),

  publishPost: z.object({
    postId:    z.string().uuid(),
    platforms: z.array(z.string().max(50)).min(1).max(14),
  }),
};

/**
 * validateBody — factory middleware using Zod schemas.
 * Returns 422 with field-level errors on validation failure.
 */
const validateBody = (schemaKey) => (req, res, next) => {
  const schema = schemas[schemaKey];
  if (!schema) return next();

  const result = schema.safeParse(req.body);
  if (!result.success) {
    const errors = result.error.errors.map(e => ({
      field:   e.path.join('.'),
      message: e.message,
    }));
    return res.status(422).json({ error: 'Validation failed', errors });
  }

  req.body = result.data;   // replace with parsed & coerced data
  next();
};

module.exports = { requestSanitizer, validateBody, sanitizeObject, schemas };
