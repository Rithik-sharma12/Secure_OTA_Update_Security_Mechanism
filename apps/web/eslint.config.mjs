// Flat ESLint config.
//
// package.json has carried a `lint: eslint .` script for a long time without
// ESLint or a config ever being installed, so `npm run lint` failed with
// "eslint: not found" and nothing in this app was ever linted.
//
// The rules below are deliberately close to `next/core-web-vitals`. The point
// of this first pass is a lint step that runs clean in CI, not a style
// overhaul; tighten it once the baseline holds.

import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import nextPlugin from '@next/eslint-plugin-next';
import reactHooks from 'eslint-plugin-react-hooks';

export default tseslint.config(
  {
    ignores: [
      '.next/**',
      'node_modules/**',
      'public/**',
      'next-env.d.ts',
      '.local-db*/**',
      '.data/**',
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ['**/*.{ts,tsx,mjs,js}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
        React: 'readonly',
      },
    },
    plugins: {
      '@next/next': nextPlugin,
      'react-hooks': reactHooks,
    },
    rules: {
      ...nextPlugin.configs.recommended.rules,
      ...nextPlugin.configs['core-web-vitals'].rules,
      ...reactHooks.configs.recommended.rules,

      // Unused locals are worth seeing, but an argument deliberately ignored
      // (or a caught error that is only rethrown) is not a defect. Underscore
      // prefix opts out, which is the convention already used in this tree.
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],

      // `any` is still common in this codebase. Warn so new ones are visible
      // without turning the first lint run into hundreds of errors.
      '@typescript-eslint/no-explicit-any': 'warn',

      'react-hooks/exhaustive-deps': 'warn',

      // eslint-plugin-react-hooks v7 enables the React Compiler rules. These
      // two fire ~30 times across the dashboard — mostly polling components
      // that call setState from inside an effect, which is a real pattern
      // worth unwinding but a refactor of its own, touching live UI with no
      // test coverage behind it yet.
      //
      // Left as warnings deliberately: CI stays green on --max-warnings=999
      // while every occurrence is still reported, so the count can be driven
      // down and the ceiling lowered. Promote both to 'error' once it hits 0.
      'react-hooks/set-state-in-effect': 'warn',
      'react-hooks/purity': 'warn',
    },
  },

  // Server-side code: Node globals, no DOM, and console output is the log.
  {
    files: ['app/api/**/*.ts', 'lib/**/*.ts', 'instrumentation.ts'],
    languageOptions: {
      globals: globals.node,
    },
    rules: {
      'no-console': 'off',
    },
  },
);
