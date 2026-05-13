'use strict';

const fs = require('fs');
const path = require('path');

describe('magic link URL handling', () => {
  it('clears the magic token before fetch in verifyMagicToken', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    const fnStart = html.indexOf('async function verifyMagicToken(token)');
    const fnEnd = html.indexOf('/* ══════════════════════════════════════', fnStart);
    const fnBody = html.slice(fnStart, fnEnd);

    expect(fnBody.indexOf("history.replaceState(null, '', '/')")).toBeGreaterThanOrEqual(0);
    expect(fnBody.indexOf("history.replaceState(null, '', '/')")).toBeLessThan(fnBody.indexOf("await fetch(base() + '/api/v1/auth/magic-link/verify'"));
  });

  it('already clears confirm and oauth tokens before fetch', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

    const confirmStart = html.indexOf('if (confirmToken)');
    const confirmBody = html.slice(confirmStart, html.indexOf('if (oauthError)', confirmStart));
    expect(confirmBody.indexOf("history.replaceState(null, '', '/')")).toBeLessThan(confirmBody.indexOf("api('POST', '/api/v1/auth/confirm-email'"));

    const oauthStart = html.indexOf('if (oauthCode)');
    const oauthBody = html.slice(oauthStart, html.indexOf('if (magicToken)', oauthStart));
    expect(oauthBody.indexOf("history.replaceState(null, '', '/')")).toBeLessThan(oauthBody.indexOf("api('POST', '/api/v1/auth/oauth/exchange'"));
  });
});
