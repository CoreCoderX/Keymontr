import * as fs from "fs";
import * as path from "path";

export interface EnvExampleResult {
  success: boolean;
  filePath: string;
  addedKeys: string[];
  error?: string;
}

/**
 * EnvExampleGenerator — Creates and maintains .env.example.
 *
 * .env.example is the safe-to-commit version of .env.
 * It contains all the keys but with placeholder values,
 * so other developers know what environment variables are needed.
 */
export class EnvExampleGenerator {
  constructor(private readonly workspaceRoot: string) {}

  /**
   * Ensures the .env.example file contains all keys from .env
   * with placeholder values (never real values).
   *
   * @param envKey - The key to add to .env.example
   * @param envFilePath - Path to the .env file to read keys from
   */
  public addKey(envKey: string, description?: string): EnvExampleResult {
    const examplePath = path.join(this.workspaceRoot, ".env.example");

    let existingContent = "";
    if (fs.existsSync(examplePath)) {
      try {
        existingContent = fs.readFileSync(examplePath, "utf-8");
      } catch (err) {
        return {
          success: false,
          filePath: examplePath,
          addedKeys: [],
          error: `Cannot read .env.example: ${String(err)}`,
        };
      }
    }

    // Check if key already exists in .env.example
    const keyRegex = new RegExp(`^${envKey}=`, "m");
    if (keyRegex.test(existingContent)) {
      return {
        success: true,
        filePath: examplePath,
        addedKeys: [],
      };
    }

    const descriptionComment =
      description !== undefined
        ? `# ${description}\n`
        : `# Required: Set this in your .env file\n`;

    const placeholder = this.buildPlaceholder(envKey);
    const newEntry =
      existingContent.length > 0
        ? `\n${descriptionComment}${envKey}=${placeholder}\n`
        : `${descriptionComment}${envKey}=${placeholder}\n`;

    try {
      fs.appendFileSync(examplePath, newEntry, "utf-8");
    } catch (err) {
      return {
        success: false,
        filePath: examplePath,
        addedKeys: [],
        error: `Cannot write .env.example: ${String(err)}`,
      };
    }

    return {
      success: true,
      filePath: examplePath,
      addedKeys: [envKey],
    };
  }

  /**
   * Builds a descriptive placeholder value for a key.
   * e.g. OPENAI_API_KEY → your-openai-api-key-here
   */
  private buildPlaceholder(envKey: string): string {
    const lower = envKey.toLowerCase().replace(/_/g, "-");
    return `your-${lower}-here`;
  }

  /**
   * Syncs .env.example with the actual .env file by adding
   * any missing keys with placeholder values.
   */
  public syncWithEnvFile(envFilePath: string): EnvExampleResult {
    if (!fs.existsSync(envFilePath)) {
      return {
        success: false,
        filePath: path.join(this.workspaceRoot, ".env.example"),
        addedKeys: [],
        error: ".env file not found",
      };
    }

    let envContent: string;
    try {
      envContent = fs.readFileSync(envFilePath, "utf-8");
    } catch (err) {
      return {
        success: false,
        filePath: path.join(this.workspaceRoot, ".env.example"),
        addedKeys: [],
        error: `Cannot read .env: ${String(err)}`,
      };
    }

    // Extract all keys from .env
    const keys: string[] = [];
    for (const line of envContent.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.length === 0 || trimmed.startsWith("#")) {
        continue;
      }
      const eqIndex = trimmed.indexOf("=");
      if (eqIndex > 0) {
        keys.push(trimmed.substring(0, eqIndex).trim());
      }
    }

    const addedKeys: string[] = [];
    for (const key of keys) {
      const result = this.addKey(key);
      if (result.addedKeys.length > 0) {
        addedKeys.push(key);
      }
    }

    return {
      success: true,
      filePath: path.join(this.workspaceRoot, ".env.example"),
      addedKeys,
    };
  }
}
