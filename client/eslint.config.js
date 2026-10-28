import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['dist/**', 'node_modules/**'],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ['**/*.{ts,tsx,js,mjs,cjs}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'no-restricted-properties': [
        'error',
        {
          property: 'innerHTML',
          message: 'innerHTML is banned by Strongroom security rules (XSS / Trusted Types violation).',
        },
        {
          property: 'outerHTML',
          message: 'outerHTML is banned by Strongroom security rules (XSS / Trusted Types violation).',
        },
        {
          property: 'insertAdjacentHTML',
          message: 'insertAdjacentHTML is banned by Strongroom security rules (XSS / Trusted Types violation).',
        },
        {
          property: 'dangerouslySetInnerHTML',
          message: 'dangerouslySetInnerHTML is banned by Strongroom security rules (PRD Section 9.2).',
        },
        {
          object: 'window',
          property: 'eval',
          message: 'eval is banned by Strongroom security rules.',
        },
        {
          object: 'globalThis',
          property: 'eval',
          message: 'eval is banned by Strongroom security rules.',
        },
        {
          object: 'Math',
          property: 'random',
          message: 'Math.random is banned (PRD Section 3). Use crypto.getRandomValues instead.',
        },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message: 'dangerouslySetInnerHTML is banned by Strongroom security rules (PRD Section 9.2).',
        },
        {
          selector: "Property[key.name='dangerouslySetInnerHTML']",
          message: 'dangerouslySetInnerHTML is banned by Strongroom security rules (PRD Section 9.2).',
        },
        {
          selector: "MemberExpression[property.name='innerHTML']",
          message: 'innerHTML is banned by Strongroom security rules.',
        },
        {
          selector: "MemberExpression[property.name='outerHTML']",
          message: 'outerHTML is banned by Strongroom security rules.',
        },
        {
          selector: "CallExpression[callee.name='eval']",
          message: 'eval is banned by Strongroom security rules.',
        },
      ],
    },
  }
);
