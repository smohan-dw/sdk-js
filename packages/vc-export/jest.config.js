module.exports = {
  preset: 'ts-jest',
  clearMocks: true,
  runner: 'groups',
  testTimeout: 10000,
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  collectCoverageFrom: [
    '**/*.ts',
    '!index.ts',
  ],
  rootDir: 'src',
  coverageDirectory: '../coverage',
}
