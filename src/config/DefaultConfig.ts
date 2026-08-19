import { KeymontrConfig } from "./ConfigurationManager.js";

/**
 * Default configuration values.
 * These are used when no .keymontr.json exists
 * or when individual fields are missing.
 */
export const DEFAULT_CONFIG: KeymontrConfig = {
  version: 1,
  detection: {
    sensitivity: "balanced",
    minimumConfidenceToWarn: 0.4,
    debounceMs: 300,
    weights: {
      regex: 0.35,
      entropy: 0.2,
      context: 0.2,
      stringGroup: 0.15,
      fileContext: 0.1,
    },
    thresholds: {
      informational: 0.4,
      low: 0.55,
      medium: 0.65,
      high: 0.75,
      critical: 0.88,
    },
  },
  git: {
    blockCommitOnCritical: true,
    blockCommitOnHigh: true,
    blockCommitOnMedium: false,
    enablePreCommitHook: true,
    hookInstallPath: ".git/hooks/pre-commit",
  },
  ui: {
    enableSounds: false,
    soundTheme: "default",
    showStatusBar: true,
    showFileDecorations: true,
    inlineSeverityIcons: true,
    showConfidenceScore: false,
  },
  ignore: {
    paths: [],
    patterns: [],
    stopwords: [],
    useDefaultIgnorePaths: true,
    useDefaultStopwords: true,
  },
  customRules: [],
  remediation: {
    autoCreateEnvFile: true,
    autoUpdateGitignore: true,
    autoCreateEnvExample: true,
    preferredEnvFileName: ".env",
  },
};

/**
 * Default stopwords — strings that significantly reduce detection confidence.
 */
export const DEFAULT_STOPWORDS: string[] = [
  "example",
  "sample",
  "placeholder",
  "dummy",
  "fake",
  "mock",
  "stub",
  "fixture",
  "test",
  "demo",
  "your",
  "mine",
  "changeme",
  "change-me",
  "replace-me",
  "replaceme",
  "insert-here",
  "inserthere",
  "todo",
  "fixme",
  "xxx",
  "yyy",
  "zzz",
  "aaa",
  "bbb",
  "ccc",
  "1234",
  "abcd",
  "n/a",
  "na",
  "none",
  "null",
  "undefined",
  "empty",
  "blank",
];

/**
 * Default excluded paths.
 */
export const DEFAULT_EXCLUDED_PATHS: string[] = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/out/**",
  "**/__pycache__/**",
  "**/*.min.js",
  "**/*.min.css",
  "**/*.bundle.js",
  "**/*.chunk.js",
  "**/coverage/**",
  "**/.nuxt/**",
  "**/.output/**",
  "**/vendor/**",
  "**/.venv/**",
  "**/venv/**",
  "**/Pods/**",
  "**/.gradle/**",
  "**/.m2/**",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml",
  "**/Gemfile.lock",
  "**/poetry.lock",
  "**/Cargo.lock",
  "**/composer.lock",
  "**/go.sum",
  "**/Pipfile.lock",
  "**/.git/**",
  "**/.svn/**",
];
