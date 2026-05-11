'use strict';

const {
  normalizeBackendUrl,
  loadBackendUrl,
  saveBackendUrl,
} = require('../public/js/backend-url');

const makeStorage = (value = '') => ({
  getItem: jest.fn(() => value),
  setItem: jest.fn(),
  removeItem: jest.fn(),
});

describe('backend URL policy', () => {
  const origin = 'https://app.example.com';

  it('allows same-origin and localhost URLs', () => {
    expect(normalizeBackendUrl('https://app.example.com/', origin, 'app.example.com')).toBe('https://app.example.com');
    expect(normalizeBackendUrl('http://localhost:4000', origin, 'localhost')).toBe('http://localhost:4000');
  });

  it('rejects foreign origins', () => {
    expect(normalizeBackendUrl('https://evil.example', origin, 'app.example.com')).toBeNull();
    expect(normalizeBackendUrl('javascript:alert(1)', origin, 'app.example.com')).toBeNull();
  });

  it('rejects localhost overrides on production hosts', () => {
    expect(normalizeBackendUrl('http://localhost:4000', origin, 'app.example.com')).toBeNull();
  });

  it('cleans invalid persisted values on load', () => {
    const storage = makeStorage('https://evil.example');

    const loaded = loadBackendUrl({ storage, origin, hostname: 'app.example.com' });

    expect(loaded).toBe('');
    expect(storage.removeItem).toHaveBeenCalledWith('omni_backend_url');
  });

  it('rejects and removes invalid saves', () => {
    const storage = makeStorage();

    const saved = saveBackendUrl({ storage, origin, hostname: 'app.example.com', candidate: 'https://evil.example' });

    expect(saved).toBeNull();
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled();
  });

  it('rejects localhost saves on production hosts', () => {
    const storage = makeStorage();

    const saved = saveBackendUrl({ storage, origin, hostname: 'app.example.com', candidate: 'http://localhost:4000' });

    expect(saved).toBeNull();
    expect(storage.setItem).not.toHaveBeenCalled();
    expect(storage.removeItem).not.toHaveBeenCalled();
  });

  it('clears the override when the input is blank', () => {
    const storage = makeStorage('http://localhost:4000');

    const saved = saveBackendUrl({ storage, origin, hostname: 'localhost', candidate: '' });

    expect(saved).toBe('');
    expect(storage.removeItem).toHaveBeenCalledWith('omni_backend_url');
  });
});
