'use strict';

const { sanitizeObject, validateBody } = require('../../middleware/sanitizer');

// ── sanitizeObject ─────────────────────────────────────────
describe('sanitizeObject', () => {
  it('strips XSS from string values', () => {
    const result = sanitizeObject({ text: '<script>alert(1)</script>Hello' });
    expect(result.text).not.toContain('<script>');
    expect(result.text).toContain('Hello');
  });

  it('strips XSS from nested objects', () => {
    const result = sanitizeObject({ a: { b: '<img onerror=alert(1)>' } });
    expect(result.a.b).not.toContain('onerror');
  });

  it('strips XSS from array elements', () => {
    const result = sanitizeObject({ tags: ['<b>bold</b>', 'safe'] });
    expect(result.tags[0]).not.toContain('<b>');
    expect(result.tags[1]).toBe('safe');
  });

  it('blocks prototype pollution keys', () => {
    const result = sanitizeObject({ __proto__: { admin: true }, name: 'ok' });
    // __proto__ must NOT be an own property on the result
    expect(Object.prototype.hasOwnProperty.call(result, '__proto__')).toBe(false);
    expect(result.name).toBe('ok');
  });

  it('blocks constructor and prototype keys', () => {
    const result = sanitizeObject({ constructor: 'x', prototype: 'y', safe: 'z' });
    expect(Object.prototype.hasOwnProperty.call(result, 'constructor')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(result, 'prototype')).toBe(false);
    expect(result.safe).toBe('z');
  });

  it('passes non-string primitives through unchanged', () => {
    const result = sanitizeObject({ count: 42, flag: true, empty: null });
    expect(result.count).toBe(42);
    expect(result.flag).toBe(true);
    expect(result.empty).toBeNull();
  });
});

// ── Zod schemas via validateBody ───────────────────────────
describe('validateBody schemas', () => {
  const mockRes = () => {
    const res = {};
    res.status = jest.fn(() => res);
    res.json   = jest.fn(() => res);
    return res;
  };

  function runValidation(schemaKey, body) {
    return new Promise((resolve) => {
      const req  = { body };
      const res  = mockRes();
      const next = jest.fn(() => resolve({ req, res, next }));
      validateBody(schemaKey)(req, res, next);
      // If next wasn't called, validation failed — resolve from res.json
      if (!next.mock.calls.length) {
        resolve({ req, res, next });
      }
    });
  }

  it('register: accepts valid input', async () => {
    const { next } = await runValidation('register', {
      email: 'user@example.com', password: 'SuperSecret123!', fullName: 'Test User',
    });
    expect(next).toHaveBeenCalled();
  });

  it('register: rejects invalid email', async () => {
    const { res } = await runValidation('register', {
      email: 'not-an-email', password: 'SuperSecret123!',
    });
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it('register: rejects password shorter than 12 chars', async () => {
    const { res } = await runValidation('register', {
      email: 'user@example.com', password: 'Short1!',
    });
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it('createPost: accepts valid input', async () => {
    const { next } = await runValidation('createPost', {
      content: 'Hello world', platforms: ['x', 'linkedin'],
    });
    expect(next).toHaveBeenCalled();
  });

  it('createPost: rejects invalid platform IDs', async () => {
    const { res } = await runValidation('createPost', {
      content: 'Hello world', platforms: ['not-a-real-platform'],
    });
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it('createPost: rejects empty content', async () => {
    const { res } = await runValidation('createPost', {
      content: '', platforms: ['x'],
    });
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it('patchPost: rejects status=published', async () => {
    const { res } = await runValidation('patchPost', { status: 'published' });
    expect(res.status).toHaveBeenCalledWith(422);
  });

  it('patchPost: accepts status=draft', async () => {
    const { next } = await runValidation('patchPost', { status: 'draft' });
    expect(next).toHaveBeenCalled();
  });

  it('patchPost: rejects unknown fields (strict mode)', async () => {
    const { res } = await runValidation('patchPost', { user_id: 'hacked' });
    expect(res.status).toHaveBeenCalledWith(422);
  });
});
