import * as fs from "fs";
import * as path from "path";
import { SecretFinding } from "../core/types/SecretFinding.js";

export interface MigrationResult {
  success: boolean;
  envFilePath: string;
  envKey: string;
  envValue: string;
  envFileCreated: boolean;
  /** True when an existing value for the key was replaced in place. */
  envValueUpdated?: boolean;
  error?: string;
}

/**
 * EnvFileMigrator — Moves a hardcoded secret into a .env file.
 *
 * Steps:
 * 1. Determine the .env file path
 * 2. Create it if it does not exist
 * 3. Check for key conflicts
 * 4. Append the key=value pair with a comment
 */
export class EnvFileMigrator {
  constructor(
    private readonly workspaceRoot: string,
    private readonly preferredEnvFileName: string = ".env",
  ) {}

  /**
   * Migrates a secret value to the .env file.
   *
   * @param finding - The secret finding to migrate
   * @returns MigrationResult with details of the operation
   */
  public migrate(finding: SecretFinding): MigrationResult {
    const envFilePath = path.join(
      this.workspaceRoot,
      this.preferredEnvFileName,
    );

    const envKey = finding.remediation.suggestedEnvKey;
    const envValue = finding.candidate.value;

    if (!envKey || envKey.length === 0) {
      return {
        success: false,
        envFilePath,
        envKey: "",
        envValue,
        envFileCreated: false,
        error: "Could not determine environment variable key name",
      };
    }

    // Validate env key format
    if (!/^[A-Z_][A-Z0-9_]*$/.test(envKey)) {
      return {
        success: false,
        envFilePath,
        envKey,
        envValue,
        envFileCreated: false,
        error: `Invalid environment variable name: ${envKey}`,
      };
    }

    const envFileCreated = !fs.existsSync(envFilePath);
    let existingContent = "";

    if (!envFileCreated) {
      try {
        existingContent = fs.readFileSync(envFilePath, "utf-8");
      } catch (err) {
        return {
          success: false,
          envFilePath,
          envKey,
          envValue,
          envFileCreated: false,
          error: `Cannot read ${this.preferredEnvFileName}: ${String(err)}`,
        };
      }

      // Key already exists — update its value in place instead of failing.
      const existingValue = this.findExistingValue(existingContent, envKey);

      if (existingValue !== null) {
        if (existingValue === envValue) {
          return {
            success: true,
            envFilePath,
            envKey,
            envValue,
            envFileCreated: false,
            envValueUpdated: false,
          };
        }

        try {
          const updatedContent = existingContent.replace(
            this.keyValuePattern(envKey),
            `${envKey}=${envValue}`,
          );
          fs.writeFileSync(envFilePath, updatedContent, "utf-8");
        } catch (err) {
          return {
            success: false,
            envFilePath,
            envKey,
            envValue,
            envFileCreated: false,
            error: `Cannot update ${envKey} in ${this.preferredEnvFileName}: ${String(err)}`,
          };
        }

        return {
          success: true,
          envFilePath,
          envKey,
          envValue,
          envFileCreated: false,
          envValueUpdated: true,
        };
      }
    }

    // Build the new entry
    const timestamp =
      new Date().toISOString().split("T")[0] ?? new Date().toISOString();
    const entryComment = `# Added by SecureShield on ${timestamp}`;
    const entryLine = `${envKey}=${envValue}`;
    const newEntry =
      existingContent.length > 0
        ? `\n${entryComment}\n${entryLine}\n`
        : `${entryComment}\n${entryLine}\n`;

    try {
      fs.appendFileSync(envFilePath, newEntry, "utf-8");
    } catch (err) {
      return {
        success: false,
        envFilePath,
        envKey,
        envValue,
        envFileCreated,
        error: `Cannot write to ${this.preferredEnvFileName}: ${String(err)}`,
      };
    }

    return {
      success: true,
      envFilePath,
      envKey,
      envValue,
      envFileCreated,
    };
  }

  /**
   * Returns the current value of a key, or null when the key is absent.
   * Handles CRLF line endings.
   */
  private findExistingValue(content: string, envKey: string): string | null {
    const match = content.match(
      new RegExp(`^${envKey}=([^\\r\\n]*)`, "m"),
    );
    return match !== null ? (match[1] ?? "") : null;
  }

  /**
   * Matches the full `KEY=value` line of a key (without the line ending).
   */
  private keyValuePattern(envKey: string): RegExp {
    return new RegExp(`^${envKey}=[^\\r\\n]*`, "m");
  }

  /**
   * Reads all existing keys from the .env file.
   */
  public getExistingEnvKeys(): string[] {
    const envFilePath = path.join(
      this.workspaceRoot,
      this.preferredEnvFileName,
    );

    if (!fs.existsSync(envFilePath)) {
      return [];
    }

    try {
      const content = fs.readFileSync(envFilePath, "utf-8");
      const keys: string[] = [];

      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.length === 0 || trimmed.startsWith("#")) {
          continue;
        }
        const eqIndex = trimmed.indexOf("=");
        if (eqIndex > 0) {
          keys.push(trimmed.substring(0, eqIndex).trim());
        }
      }

      return keys;
    } catch {
      return [];
    }
  }
}
