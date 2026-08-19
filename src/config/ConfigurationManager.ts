import * as fs from "fs";
import * as path from "path";
import { ConfigValidator } from "./ConfigValidator.js";
import {
  DEFAULT_CONFIG,
  DEFAULT_STOPWORDS,
  DEFAULT_EXCLUDED_PATHS,
} from "./DefaultConfig.js";
import { CustomRule } from "../core/types/RuleDefinition.js";

/**
 * Full configuration schema for Keymontr.
 */
export interface KeymontrConfig {
  version: number;
  detection: {
    sensitivity: "strict" | "balanced" | "relaxed";
    minimumConfidenceToWarn: number;
    debounceMs: number;
    weights: {
      regex: number;
      entropy: number;
      context: number;
      stringGroup: number;
      fileContext: number;
    };
    thresholds: {
      informational: number;
      low: number;
      medium: number;
      high: number;
      critical: number;
    };
  };
  git: {
    blockCommitOnCritical: boolean;
    blockCommitOnHigh: boolean;
    blockCommitOnMedium: boolean;
    enablePreCommitHook: boolean;
    hookInstallPath: string;
  };
  ui: {
    enableSounds: boolean;
    soundTheme: "default" | "minimal" | "none";
    showStatusBar: boolean;
    showFileDecorations: boolean;
    inlineSeverityIcons: boolean;
    showConfidenceScore: boolean;
  };
  ignore: {
    paths: string[];
    patterns: string[];
    stopwords: string[];
    useDefaultIgnorePaths: boolean;
    useDefaultStopwords: boolean;
  };
  customRules: CustomRule[];
  remediation: {
    autoCreateEnvFile: boolean;
    autoUpdateGitignore: boolean;
    autoCreateEnvExample: boolean;
    preferredEnvFileName: string;
  };
}

/**
 * Manages loading, validation, and watching of .keymontr.json.
 *
 * Merges user config with defaults so all fields always have a value.
 */
export class ConfigurationManager {
  private config: KeymontrConfig = structuredClone(DEFAULT_CONFIG);
  private validator = new ConfigValidator();
  private configFilePath: string | null = null;
  private validationWarnings: string[] = [];

  /**
   * Loads configuration from the workspace root.
   * Falls back to defaults if no config file exists.
   *
   * @param workspaceRootPath - Absolute path to the workspace root
   * @param configFileName - Config file name (default: .keymontr.json)
   */
  public load(
    workspaceRootPath: string,
    configFileName = ".keymontr.json",
  ): void {
    this.configFilePath = path.join(workspaceRootPath, configFileName);

    if (!fs.existsSync(this.configFilePath)) {
      // No config file — use defaults silently
      this.config = structuredClone(DEFAULT_CONFIG);
      return;
    }

    let raw: string;
    try {
      raw = fs.readFileSync(this.configFilePath, "utf-8");
    } catch (err) {
      // Cannot read file — use defaults
      this.config = structuredClone(DEFAULT_CONFIG);
      this.validationWarnings.push(
        `Could not read .keymontr.json: ${String(err)}. Using defaults.`,
      );
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      this.config = structuredClone(DEFAULT_CONFIG);
      this.validationWarnings.push(
        `Could not parse .keymontr.json: ${String(err)}. Using defaults.`,
      );
      return;
    }

    const validation = this.validator.validate(parsed);

    if (!validation.valid) {
      // Config has errors — use defaults and report
      this.config = structuredClone(DEFAULT_CONFIG);
      this.validationWarnings.push(
        `Invalid .keymontr.json: ${validation.errors.join(", ")}. Using defaults.`,
      );
      return;
    }

    this.validationWarnings = validation.warnings;
    this.config = this.mergeWithDefaults(parsed as Partial<KeymontrConfig>);
  }

  /**
   * Deep merges user config with defaults.
   * User values override defaults, missing fields use defaults.
   */
  private mergeWithDefaults(
    userConfig: Partial<KeymontrConfig>,
  ): KeymontrConfig {
    const defaults = structuredClone(DEFAULT_CONFIG);

    return {
      version: userConfig.version ?? defaults.version,
      detection: {
        ...defaults.detection,
        ...userConfig.detection,
        weights: {
          ...defaults.detection.weights,
          ...userConfig.detection?.weights,
        },
        thresholds: {
          ...defaults.detection.thresholds,
          ...userConfig.detection?.thresholds,
        },
      },
      git: {
        ...defaults.git,
        ...userConfig.git,
      },
      ui: {
        ...defaults.ui,
        ...userConfig.ui,
      },
      ignore: {
        ...defaults.ignore,
        ...userConfig.ignore,
        paths: userConfig.ignore?.paths ?? defaults.ignore.paths,
        patterns: userConfig.ignore?.patterns ?? defaults.ignore.patterns,
        stopwords: userConfig.ignore?.stopwords ?? defaults.ignore.stopwords,
      },
      customRules: userConfig.customRules ?? defaults.customRules,
      remediation: {
        ...defaults.remediation,
        ...userConfig.remediation,
      },
    };
  }

  /**
   * Returns the effective configuration.
   */
  public getConfig(): KeymontrConfig {
    return this.config;
  }

  /**
   * Returns the effective list of excluded paths (user + defaults if enabled).
   */
  public getEffectiveIgnorePaths(): string[] {
    const paths = [...this.config.ignore.paths];
    if (this.config.ignore.useDefaultIgnorePaths) {
      paths.push(...DEFAULT_EXCLUDED_PATHS);
    }
    return [...new Set(paths)]; // Deduplicate
  }

  /**
   * Returns the effective list of stopwords (user + defaults if enabled).
   */
  public getEffectiveStopwords(): string[] {
    const words = [...this.config.ignore.stopwords];
    if (this.config.ignore.useDefaultStopwords) {
      words.push(...DEFAULT_STOPWORDS);
    }
    return [...new Set(words.map((w) => w.toLowerCase()))];
  }

  /**
   * Returns validation warnings from the last load() call.
   */
  public getValidationWarnings(): string[] {
    return this.validationWarnings;
  }

  /**
   * Returns the path to the config file (may be null if not set).
   */
  public getConfigFilePath(): string | null {
    return this.configFilePath;
  }

  /**
   * Reloads the configuration from disk.
   */
  public reload(workspaceRootPath: string): void {
    this.load(workspaceRootPath);
  }
}
