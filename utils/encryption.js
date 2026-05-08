/**
 * utils/encryption.js — AES-256-GCM token encryption at rest
 * Covers: GDPR Art. 32 · SOC 2 CC6.7
 */

'use strict';

const crypto = require('crypto');

const ALGO    = 'aes-256-gcm';
const KEY     = Buffer.from(process.env.ENCRYPTION_KEY || '', 'hex');
const IV_LEN  = 16;

if (process.env.NODE_ENV === 'production' && KEY.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be a 32-byte (64-char hex) string');
}

/**
 * encrypt — encrypts plaintext using AES-256-GCM.
 * Returns: iv(hex):tag(hex):ciphertext(hex)
 */
const encrypt = (plaintext) => {
  const iv     = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const enc    = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return `${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
};

/**
 * decrypt — decrypts an AES-256-GCM ciphertext string.
 */
const decrypt = (ciphertext) => {
  const [ivHex, tagHex, encHex] = ciphertext.split(':');
  if (!ivHex || !tagHex || !encHex) throw new Error('Invalid ciphertext format');
  const iv       = Buffer.from(ivHex,  'hex');
  const tag      = Buffer.from(tagHex, 'hex');
  const enc      = Buffer.from(encHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
};

module.exports = { encrypt, decrypt };
