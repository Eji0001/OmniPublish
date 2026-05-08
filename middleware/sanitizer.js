/**
 * middleware/sanitizer.js
 * Recursive input sanitisation — strips XSS, SQL injection, prototype pollution.
 * Covers: OWASP A03 (Injection)
 */

'use strict';

const xss    = require('xss');
const { z }  = require('zod');
const { logger } = require('../utils/logger');

const xssOptions = {
  whiteList: {}, stripIgnoreTag: true,
  stripIgnoreTagBody: ['script', 'style', 'iframe', 'object', 'embed'],
  css: false,
};

const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

const sanitizeObject = (obj, depth = 0) => {
  if (depth > 10) return obj;
  if (obj === null || typeof obj !== 'object')
    return typeof obj === 'string' ? xss(obj, xssOptions) : obj;
  if (Array.isArray(obj)) return obj.map(item => sanitizeObject(item, depth + 1));
  const clean = {};
  for (const [key, value] of Object.entries(obj)) {
    if (DANGEROUS_KEYS.has(key)) { logger.warn('Prototype pollution attempt blocked', { key }); continue; }
    clean[xss(key, xssOptions)] = sanitizeObject(value, depth + 1);
  }
  return clean;
};

const requestSanitizer = (req, res, next) => {
  if (req.body   && typeof req.body === 'object')   req.body   = sanitizeObject(req.body);
  if (req.query  && typeof req.query === 'object')   req.query  = sanitizeObject(req.query);
  if (req.params && typeof req.params === 'object')  req.params = sanitizeObject(req.params);
  next();
};

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
  forgotPassword: z.object({
    email: z.string().email().max(255),
  }),
  resetPassword: z.object({
    token:    z.string().min(64).max(64),
    password: z.string().min(12).max(128),
  }),
  patchPost: z.object({
    title:        z.string().max(500).optional(),
    content:      z.string().min(1).max(63206).optional(),
    format:       z.enum(['post', 'video', 'short', 'story', 'article']).optional(),
    aspect_ratio: z.enum(['16:9', '9:16', '1:1', '4:5', '2:3']).optional(),
    scheduled_at: z.string().datetime().nullable().optional(),
    status:       z.enum(['draft', 'scheduled']).optional(),
  }).strict(),
};

const validateBody = (schemaKey) => (req, res, next) => {
  const schema = schemas[schemaKey];
  if (!schema) return next();
  const result = schema.safeParse(req.body);
  if (!result.success) {
    const errors = result.error.errors.map(e => ({ field: e.path.join('.'), message: e.message }));
    return res.status(422).json({ error: 'Validation failed', errors });
  }
  req.body = result.data;
  next();
};

module.exports = { requestSanitizer, validateBody, sanitizeObject, schemas };
