/** @type {import("jest").Config} */
const config = {
  rootDir: ".",

  testEnvironment: "node",

  testMatch: [
    "<rootDir>/tests/**/*.test.ts"
  ],

  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        tsconfig: "<rootDir>/tsconfig.test.json"
      }
    ]
  },

  moduleNameMapper: {
    /*
     * Source files import with ESM-style ".js" specifiers (e.g.
     * "../types/DetectionResult.js"). Strip the extension so Jest's
     * resolver finds the underlying TypeScript file.
     */
    "^(\.{1,2}/.*)\.js$": "$1",

    "^@core/(.*)$": "<rootDir>/src/core/$1",
    "^@database/(.*)$": "<rootDir>/src/database/$1",
    "^@vscode/(.*)$": "<rootDir>/src/vscode/$1",
    "^@git/(.*)$": "<rootDir>/src/git/$1",
    "^@remediation/(.*)$": "<rootDir>/src/remediation/$1",
    "^@storage/(.*)$": "<rootDir>/src/storage/$1",
    "^@config/(.*)$": "<rootDir>/src/config/$1",
    "^@ai/(.*)$": "<rootDir>/src/ai/$1",

    "^vscode$": "<rootDir>/tests/__mocks__/vscode.ts"
  },

  moduleFileExtensions: [
    "ts",
    "js",
    "json"
  ],

  clearMocks: true,
  restoreMocks: true,

  collectCoverageFrom: [
    "src/**/*.ts",

    "!src/extension.ts",
    "!src/vscode/**/*.ts",
    "!src/**/*.d.ts"
  ],

  coverageDirectory: "<rootDir>/coverage",

  coverageReporters: [
    "text",
    "text-summary",
    "lcov",
    "html"
  ],

  coverageThreshold: {
    global: {
      branches: 80,
      functions: 85,
      lines: 85,
      statements: 85
    }
  },

  testTimeout: 30_000,

  passWithNoTests: false
};

module.exports = config;
