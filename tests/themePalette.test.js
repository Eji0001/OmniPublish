'use strict';

const fs = require('fs');
const path = require('path');

describe('dark theme palette', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

  it('uses a flatter near-black dark palette', () => {
    expect(html).toContain('[data-theme="dark"]{--bg:linear-gradient(180deg,#090a0c 0%,#050506 100%)');
    expect(html).toContain('--s1:#0b0c0e;--s2:#101214;--s3:#16191c;--s4:#1d2126');
    expect(html).toContain('--acc:#8db7e8');
    expect(html).toContain('--btn-grad:linear-gradient(135deg,#151a21,#0d1116)');
  });

  it('uses a subtle neutral background wash', () => {
    expect(html).toContain('radial-gradient(ellipse 95% 62% at 50% -10%,rgba(255,255,255,0.035),transparent)');
    expect(html).toContain('radial-gradient(ellipse 62% 44% at 82% 82%,rgba(255,255,255,0.018),transparent)');
  });
});
