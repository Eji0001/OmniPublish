'use strict';

const { encrypt, decrypt } = require('../../utils/encryption');

describe('encryption (AES-256-GCM)', () => {
  it('round-trips plaintext correctly', () => {
    const plain = 'super-secret-oauth-token-12345';
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it('produces unique ciphertexts for the same input (random IV)', () => {
    const plain = 'same-input';
    expect(encrypt(plain)).not.toBe(encrypt(plain));
  });

  it('round-trips unicode and special characters', () => {
    const plain = '日本語テスト 🔒 <script>alert(1)</script>';
    expect(decrypt(encrypt(plain))).toBe(plain);
  });

  it('throws on a tampered ciphertext (auth tag mismatch)', () => {
    const [iv, tag, ct] = encrypt('data').split(':');
    const tampered = `${iv}:${tag}:${'ff'.repeat(ct.length / 2)}`;
    expect(() => decrypt(tampered)).toThrow();
  });

  it('throws on a malformed ciphertext (wrong format)', () => {
    expect(() => decrypt('not-valid-format')).toThrow('Invalid ciphertext format');
  });

  it('throws on a truncated ciphertext', () => {
    expect(() => decrypt('aabb:ccdd')).toThrow('Invalid ciphertext format');
  });
});
