/** @type {import('jest').Config} */
export default {
  // verbose: true, // Uncomment for detailed test output
  collectCoverage: true,
  coverageDirectory: 'coverage',
  testEnvironment: 'jsdom',
  testEnvironmentOptions: {
    customExportConditions: ['node'],
  },
  testPathIgnorePatterns: ['/node_modules/', '/dist/'],
  // Transform ESM packages (solid-oidc and jose)
  transformIgnorePatterns: [
    '/node_modules/(?!(solid-oidc|jose)/)',
  ],
  // Map CDN imports to npm packages for testing
  moduleNameMapper: {
    '^https://esm\\.sh/jose@5$': 'jose',
  },
  transform: {
    '^.+\\.[tj]sx?$': ['babel-jest', { configFile: './babel.config.mjs' }],
  },
  setupFilesAfterEnv: ['./test/helpers/setup.ts'],
  testMatch: ['**/__tests__/**/*.ts?(x)', '**/?(*.)+(spec|test).ts?(x)'],
  roots: ['<rootDir>/src', '<rootDir>/test'],
}