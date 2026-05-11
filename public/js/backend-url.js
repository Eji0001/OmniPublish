'use strict';

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.OmniPublishBackendUrl = factory();
  }
}(typeof globalThis !== 'undefined' ? globalThis : window, function () {
  const STORAGE_KEY = 'omni_backend_url';
  const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

  const isAllowedHost = (hostname) => {
    const host = String(hostname || '').toLowerCase();
    return LOCALHOST_HOSTS.has(host) || /^127(?:\.\d{1,3}){3}$/.test(host);
  };

  const isDevHost = (hostname) => isAllowedHost(hostname);

  const normalizeBackendUrl = (candidate, origin, hostname) => {
    const raw = String(candidate || '').trim().replace(/\/$/, '');
    if (!raw) return '';

    let url;
    try {
      url = new URL(raw, origin);
    } catch {
      return '';
    }

    if (!['http:', 'https:'].includes(url.protocol)) return null;
    if (url.pathname !== '/' || url.search || url.hash) return null;
    if (url.origin !== origin && !(isDevHost(hostname) && isAllowedHost(url.hostname))) return null;

    return url.origin;
  };

  const loadBackendUrl = ({ storage, origin, hostname, storageKey = STORAGE_KEY }) => {
    if (!storage) return '';
    const stored = storage.getItem(storageKey) || '';
    const normalized = normalizeBackendUrl(stored, origin, hostname || ((typeof window !== 'undefined' && window.location?.hostname) || ''));
    if (stored && !normalized) storage.removeItem(storageKey);
    return normalized || '';
  };

  const saveBackendUrl = ({ storage, origin, hostname, candidate, storageKey = STORAGE_KEY }) => {
    const normalized = normalizeBackendUrl(candidate, origin, hostname);
    if (storage) {
      if (normalized === '') storage.removeItem(storageKey);
      if (normalized) storage.setItem(storageKey, normalized);
    }
    return normalized;
  };

  return {
    STORAGE_KEY,
    isAllowedHost,
    isDevHost,
    normalizeBackendUrl,
    loadBackendUrl,
    saveBackendUrl,
  };
}));
