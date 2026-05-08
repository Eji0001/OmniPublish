'use strict';

const js = require('@eslint/js');

module.exports = [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        require:   'readonly',
        module:    'readonly',
        exports:   'readonly',
        __dirname: 'readonly',
        __filename:'readonly',
        process:   'readonly',
        Buffer:    'readonly',
        console:   'readonly',
        setTimeout:'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        URL:       'readonly',
        URLSearchParams: 'readonly',
        fetch:     'readonly',
      },
    },
    rules: {
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console':     'off',
      'eqeqeq':         ['error', 'always'],
      'no-var':         'error',
      'prefer-const':   'error',
    },
  },
  {
    files: ['tests/**/*.js'],
    languageOptions: {
      globals: {
        describe:   'readonly',
        it:         'readonly',
        test:       'readonly',
        expect:     'readonly',
        beforeEach: 'readonly',
        afterEach:  'readonly',
        beforeAll:  'readonly',
        afterAll:   'readonly',
        jest:       'readonly',
      },
    },
  },
  {
    ignores: ['node_modules/**', 'coverage/**', 'db/**'],
  },
];
