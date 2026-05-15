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

function makeElement() {
  return {
    textContent: '',
    title: '',
    disabled: false,
    classList: makeClassList(),
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
    extractFunction(html, 'function selectRole(card, role)', 'function renderOnboardingIntro()'),
  ].join('\n');

  function buildContext(existingRole = '') {
    const cards = ['founder', 'creator', 'agency'].map(role => ({
      dataset: { role },
      disabled: false,
      classList: makeClassList(),
    }));

    const elements = {
      'ob-add-facebook': makeElement(),
      'ob-plat-facebook': makeElement(),
      'ob-plat-state-facebook': makeElement(),
      'settings-status': makeElement(),
    };

    const document = {
      querySelectorAll: jest.fn(() => cards),
      getElementById: jest.fn((id) => elements[id] || null),
    };

    const localStorage = {
      getItem: jest.fn(() => existingRole),
      setItem: jest.fn(),
    };

    const api = jest.fn(() => Promise.resolve({ ok: true }));
    const obGoStep = jest.fn();
    const finishOnboarding = jest.fn();
    const toast = jest.fn();

    const context = {
      document,
      localStorage,
      api,
      obGoStep,
      finishOnboarding,
      toast,
      setTimeout,
      clearTimeout,
      requestAnimationFrame: (fn) => fn(),
    };

    vm.createContext(context);
    vm.runInContext(`var _onboardingStep = 1;\nvar _platformConnections = {};\nvar _selectedPersona = ${JSON.stringify(existingRole)};\n${source}`, context);
    return { context, cards, localStorage, api, obGoStep, finishOnboarding, toast, elements };
  }

  beforeEach(() => jest.useFakeTimers());
  afterEach(() => jest.useRealTimers());

  it('keeps the selected persona highlighted until continue is clicked', async () => {
    const { context, cards, localStorage, api, obGoStep } = buildContext();

    const selection = context.selectRole(cards[1], 'creator');
    expect(selection).toBeUndefined();
    expect(cards[1].classList.contains('selected')).toBe(true);
    expect(cards[0].disabled).toBe(true);
    expect(cards[1].disabled).toBe(true);
    expect(cards[2].disabled).toBe(true);
    expect(localStorage.setItem).toHaveBeenCalledWith('omni_user_role', 'creator');
    expect(api).toHaveBeenCalledWith('PATCH', '/api/v1/auth/me/profile', { userType: 'creator' });
    expect(obGoStep).not.toHaveBeenCalled();

    context.nextOnboardingStep();
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

  it('blocks onboarding progression on step 2 until a connection exists', () => {
    const { context, obGoStep, toast } = buildContext();

    context._onboardingStep = 2;
    context._platformConnections = {};
    context.nextOnboardingStep();

    expect(toast).toHaveBeenCalledWith('Connect at least one channel to continue.', 'err');
    expect(obGoStep).not.toHaveBeenCalledWith(3);

    context._platformConnections = { facebook: { platform: 'facebook', is_active: true } };
    context.nextOnboardingStep();
    expect(obGoStep).toHaveBeenCalledWith(3);
  });

  it('marks connected channels with a highlighted card and check state', () => {
    const { context, elements } = buildContext();

    context._platformConnections = { facebook: { platform: 'facebook', is_active: true } };
    context.syncPlatformCard('facebook');

    expect(elements['ob-add-facebook'].textContent).toBe('✓ Connected');
    expect(elements['ob-plat-facebook'].classList.contains('connected')).toBe(true);
    expect(elements['ob-plat-state-facebook'].textContent).toBe('Connected');
  });
});
