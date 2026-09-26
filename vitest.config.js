import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node is the default. Individual test files that need a DOM add
    // `// @vitest-environment jsdom` at the top — we do NOT want jsdom
    // overhead on the pure-module suites.
    environment: 'node',
    globals: false,
    include: ['tests/**/*.test.js'],
    exclude: ['node_modules/**', 'dist/**'],
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: [
        'core/**/*.js',
        'heuristics.js',
        'dnr.js',
        'security.js'
      ],
      exclude: [
        'core/providers/**',
        // i18n.js is enormous and largely data — coverage there is
        // not a meaningful signal.
        'core/i18n.js'
      ]
    }
  }
});