/**
 * Jest CI/CD Configuration
 *
 * Optimized configuration for continuous integration environments.
 * Uses parallel execution with limited workers, enforces coverage thresholds,
 * and provides detailed output for debugging.
 */

const baseConfig = require('./jest.config.js');

module.exports = {
  ...baseConfig,

  // CI-specific settings
  ci: true,

  // Limit workers to prevent resource exhaustion in CI
  maxWorkers: 2,

  // Increase timeout for slower CI environments
  testTimeout: 30000,

  // Fail fast - stop on first failure for faster feedback
  bail: 1,

  // Verbose output for CI logs
  verbose: true,

  // Coverage configuration
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'json-summary', 'cobertura'],

  // Coverage thresholds - fail if coverage drops below these values
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 75,
      lines: 75,
      statements: 75,
    },
    // Critical paths require higher coverage
    './tests/unit/crypto/**/*.ts': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90,
    },
    './tests/security/**/*.ts': {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },

  // Coverage collection from source files
  collectCoverageFrom: [
    'tests/**/*.ts',
    '!tests/**/*.d.ts',
    '!tests/**/index.ts',
    '!tests/setup.ts',
    '!tests/**/*.config.js',
  ],

  // Reporters for CI output
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: 'test-results',
        outputName: 'junit.xml',
        classNameTemplate: '{classname}',
        titleTemplate: '{title}',
        ancestorSeparator: ' > ',
        usePathForSuiteName: true,
      },
    ],
  ],

  // Cache for faster subsequent runs
  cache: true,
  cacheDirectory: '.jest-cache',

  // Error handling
  errorOnDeprecated: true,

  // Force exit after tests complete (prevents hanging)
  forceExit: true,

  // Detect open handles (useful for debugging)
  detectOpenHandles: true,

  // Run tests in band for more predictable output
  // Uncomment if parallelization causes issues:
  // runInBand: true,
};
