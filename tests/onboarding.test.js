'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

function makeClassList() {
  const classes = new Set();
  return {
    add: (...names) => names.forEach(name => classes.add(name)),
    remove: (...names) => names.forEach(name => classes.delete(name)),
    toggle: (name, force) => {
      if (force) classes.add(name);
      else classes.delete(name);
    },
    contains: (name) => classes.has(name),
    toString: () => [...classes].join(' '),
  };
}

function extractFunction(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start);
  if (start === -1 || end === -1) throw new Error(`Could not extract ${startMarker}`);
  return source.slice(start, end);
}

describe('onboarding persona selection', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
  const source = [
    extractFunction(html, 'function syncPersonaSelection(role)', 'function obGoStep(n)'),
    extractFunction(html, 'function selectRole(card, role)', 'function updateFrequencyDisplay(value)'),
  ].join('\n');

  function buildContext(existingRole = '') {
    const cards = ['founder', 'creator', 'agency'].map(role => ({
      dataset: { role },
      disabled: false,
      classList: makeClassList(),
    }));

    const document = {
      querySelectorAll: jest.fn(() => cards),
    };

    const localStorage = {
      getItem: jest.fn(() => existingRole),
      setItem: jest.fn(),
    };

    const api = jest.fn(() => Promise.resolve({ ok: true }));
    const obGoStep = jest.fn();

    const context = {
      document,
      localStorage,
      api,
      obGoStep,
      setTimeout,
      clearTimeout,
    };

    vm.createContext(context);
    vm.runInContext(`let _selectedPersona = ${JSON.stringify(existingRole)};\n${source}`, context);
    return { context, cards, localStorage, api, obGoStep };
  }

  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('keeps the selected persona highlighted and locks the other choices', async () => {
    const { context, cards, localStorage, api, obGoStep } = buildContext();

    const selection = context.selectRole(cards[1], 'creator');
    expect(selection).toBeUndefined();
    expect(cards[1].classList.contains('selected')).toBe(true);
    expect(cards[0].disabled).toBe(true);
    expect(cards[1].disabled).toBe(true);
    expect(cards[2].disabled).toBe(true);
    expect(localStorage.setItem).toHaveBeenCalledWith('omni_user_role', 'creator');
    expect(api).toHaveBeenCalledWith('PATCH', '/api/v1/auth/me/profile', { userType: 'creator' });

    context.selectRole(cards[0], 'founder');
    expect(localStorage.setItem).toHaveBeenCalledTimes(1);

    await jest.advanceTimersByTimeAsync(549);
    expect(obGoStep).not.toHaveBeenCalled();

    await jest.advanceTimersByTimeAsync(1);
    expect(obGoStep).toHaveBeenCalledWith(2);
  });

  it('restores the highlighted persona from saved state', () => {
    const { context, cards } = buildContext('agency');
    context.syncPersonaSelection('agency');

    expect(cards[2].classList.contains('selected')).toBe(true);
    expect(cards[0].disabled).toBe(true);
    expect(cards[1].disabled).toBe(true);
    expect(cards[2].disabled).toBe(true);
  });
});
