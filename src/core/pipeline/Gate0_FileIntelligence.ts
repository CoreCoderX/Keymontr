import * as path from "path";
import {
  FileRiskLevel,
  FILE_RISK_MULTIPLIERS,
} from "../types/DetectionResult.js";

/**
 * Gate 0 — File Intelligence Layer
 *
 * The cheapest gate — eliminates entire file categories before any processing.
 * Assigns risk multipliers to files that pass through.
 *
 * Decision order:
 * 1. Binary extension → EXCLUDED
 * 2. Matches exclusion glob pattern → EXCLUDED
 * 3. Matches high-risk file name/path → HIGH or ELEVATED
 * 4. Matches reduced-risk pattern → REDUCED
 * 5. Everything else → NORMAL
 */

export interface Gate0Result {
  shouldScan: boolean;
  riskLevel: FileRiskLevel;
  riskMultiplier: number;
  reason: string;
}

// Binary file extensions — never scan these
const BINARY_EXTENSIONS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".bmp",
  ".ico",
  ".webp",
  ".tiff",
  ".avif",
  ".mp4",
  ".mp3",
  ".wav",
  ".avi",
  ".mov",
  ".mkv",
  ".flv",
  ".ogg",
  ".webm",
  ".pdf",
  ".doc",
  ".docx",
  ".xls",
  ".xlsx",
  ".ppt",
  ".pptx",
  ".odt",
  ".zip",
  ".tar",
  ".gz",
  ".rar",
  ".7z",
  ".bz2",
  ".xz",
  ".lz4",
  ".zst",
  ".exe",
  ".dll",
  ".so",
  ".dylib",
  ".lib",
  ".a",
  ".o",
  ".obj",
  ".woff",
  ".woff2",
  ".ttf",
  ".eot",
  ".otf",
  ".class",
  ".jar",
  ".war",
  ".ear",
  ".pyc",
  ".pyo",
  ".pyd",
  ".db",
  ".sqlite",
  ".sqlite3",
  ".bin",
  ".dat",
  ".pak",
  ".map", // Source maps — large, not useful for secret detection
]);

// File names (basename only) that indicate HIGH risk
const HIGH_RISK_BASENAMES = new Set([
  ".env",
  "secrets.json",
  "credentials.json",
  "credentials.yaml",
  "credentials.yml",
  "service-account.json",
  "serviceaccount.json",
  "keyfile.json",
  "key.json",
  "secret.json",
  "private.json",
  ".netrc",
  ".pgpass",
  ".my.cnf",
  ".boto",
  ".s3cfg",
  "kubeconfig",
]);

// File name prefix patterns that indicate HIGH risk
const HIGH_RISK_PREFIXES = [".env."];

// File names that indicate ELEVATED risk
const ELEVATED_RISK_BASENAMES = new Set([
  "application.yml",
  "application.yaml",
  "application.properties",
  "config.json",
  "config.yaml",
  "config.yml",
  "config.toml",
  "settings.json",
  "settings.py",
  "settings.yaml",
  "settings.yml",
  "docker-compose.yml",
  "docker-compose.yaml",
  "docker-compose.override.yml",
  "docker-compose.override.yaml",
  "terraform.tfvars",
  "terraform.tfvars.json",
  ".terraform.tfvars",
  "values.yaml",
  "values.yml",
  "helm-values.yaml",
  "vault.yaml",
  "vault.yml",
]);

// Path segment patterns that indicate REDUCED risk
const REDUCED_RISK_PATH_SEGMENTS = [
  /[/\\]tests?[/\\]/i,
  /[/\\]__tests__[/\\]/i,
  /[/\\]specs?[/\\]/i,
  /[/\\]mocks?[/\\]/i,
  /[/\\]fixtures?[/\\]/i,
  /[/\\]examples?[/\\]/i,
  /[/\\]docs?[/\\]/i,
  /[/\\]documentation[/\\]/i,
  /[/\\]samples?[/\\]/i,
  /[/\\]demos?[/\\]/i,
];

// File extension patterns that indicate REDUCED risk
const REDUCED_RISK_EXTENSIONS = new Set([
  ".md",
  ".mdx",
  ".rst",
  ".txt",
  ".adoc",
  ".asciidoc",
]);

// File name suffix patterns that indicate REDUCED risk (test files)
const REDUCED_RISK_SUFFIXES = [
  ".test.ts",
  ".test.js",
  ".test.tsx",
  ".test.jsx",
  ".spec.ts",
  ".spec.js",
  ".spec.tsx",
  ".spec.jsx",
  ".test.py",
  "_test.go",
  "_test.rs",
];

export class Gate0_FileIntelligence {
  private readonly exclusionPatterns: RegExp[];

  constructor(excludedGlobs: string[]) {
    this.exclusionPatterns = excludedGlobs
      .map((glob) => this.globToRegex(glob))
      .filter((r): r is RegExp => r !== null);
  }

  /**
   * Converts a glob pattern to a RegExp.
   * Supports ** and * wildcards.
   */
  private globToRegex(glob: string): RegExp | null {
    try {
      const escaped = glob
        .replace(/\\/g, "/")
        .replace(/[.+^${}()|[\]]/g, "\\$&")
        .replace(/\*\*/g, "§DOUBLE§")
        .replace(/\*/g, "[^/]*")
        .replace(/§DOUBLE§/g, ".*");
      return new RegExp(escaped, "i");
    } catch {
      return null;
    }
  }

  /**
   * Assesses a file and returns whether it should be scanned
   * and at what risk level.
   *
   * @param filePath - Absolute or workspace-relative file path
   */
  public assess(filePath: string): Gate0Result {
    const normalized = filePath.replace(/\\/g, "/");
    const ext = path.extname(filePath).toLowerCase();
    const basename = path.basename(filePath);
    const baseLower = basename.toLowerCase();

    // 1. Binary extension check (fastest path — O(1))
    if (BINARY_EXTENSIONS.has(ext)) {
      return this.excluded(`Binary file extension: ${ext}`);
    }

    // 2. Exclusion glob patterns (build output, node_modules, lock files, etc.)
    for (const pattern of this.exclusionPatterns) {
      if (pattern.test(normalized)) {
        return this.excluded(`Matched exclusion pattern: ${pattern.source}`);
      }
    }

    // 3. HIGH risk — known secret file names
    if (HIGH_RISK_BASENAMES.has(baseLower)) {
      return this.risk(FileRiskLevel.HIGH, `Known secret file: ${basename}`);
    }

    // .env.production, .env.local, .env.anything
    for (const prefix of HIGH_RISK_PREFIXES) {
      if (baseLower.startsWith(prefix)) {
        return this.risk(FileRiskLevel.HIGH, `Environment file: ${basename}`);
      }
    }

    // 4. ELEVATED risk — config files
    if (ELEVATED_RISK_BASENAMES.has(baseLower)) {
      return this.risk(
        FileRiskLevel.ELEVATED,
        `Configuration file: ${basename}`,
      );
    }

    // 5. REDUCED risk — test path segments
    for (const pattern of REDUCED_RISK_PATH_SEGMENTS) {
      if (pattern.test(normalized)) {
        return this.risk(
          FileRiskLevel.REDUCED,
          `Test/documentation path detected`,
        );
      }
    }

    // 6. REDUCED risk — documentation extensions
    if (REDUCED_RISK_EXTENSIONS.has(ext)) {
      return this.risk(
        FileRiskLevel.REDUCED,
        `Documentation file extension: ${ext}`,
      );
    }

    // 7. REDUCED risk — test file suffixes
    for (const suffix of REDUCED_RISK_SUFFIXES) {
      if (baseLower.endsWith(suffix)) {
        return this.risk(FileRiskLevel.REDUCED, `Test file suffix: ${suffix}`);
      }
    }

    // 8. Default — normal source file
    return this.risk(FileRiskLevel.NORMAL, "Regular source file");
  }

  private excluded(reason: string): Gate0Result {
    return {
      shouldScan: false,
      riskLevel: FileRiskLevel.EXCLUDED,
      riskMultiplier: 0,
      reason,
    };
  }

  private risk(level: FileRiskLevel, reason: string): Gate0Result {
    return {
      shouldScan: true,
      riskLevel: level,
      riskMultiplier: FILE_RISK_MULTIPLIERS[level],
      reason,
    };
  }

  /**
   * Adds additional exclusion patterns at runtime (e.g. from user config).
   */
  public addExclusionPattern(glob: string): void {
    const regex = this.globToRegex(glob);
    if (regex !== null) {
      this.exclusionPatterns.push(regex);
    }
  }
}
