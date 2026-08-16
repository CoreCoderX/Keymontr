import * as fs from "fs";
import * as path from "path";

export interface GitignoreUpdateResult {
  success: boolean;
  addedEntries: string[];
  alreadyPresent: string[];
  error?: string;
}

/**
 * GitignoreUpdater — Ensures sensitive files are in .gitignore.
 *
 * Checks for the presence of each entry and only adds missing ones.
 * Preserves all existing content and comments.
 */
export class GitignoreUpdater {
  private static readonly SECURESHIELD_SECTION_HEADER =
    "# SecureShield — automatically added";

  constructor(private readonly workspaceRoot: string) {}

  /**
   * Ensures all given entries are present in .gitignore.
   *
   * @param entriesToEnsure - List of patterns to ensure (e.g., [".env", ".env.*"])
   */
  public ensureEntries(
    entriesToEnsure: string[],
  ): GitignoreUpdateResult {
    const gitignorePath = path.join(this.workspaceRoot, ".gitignore");

    let existingContent = "";
    const gitignoreExists = fs.existsSync(gitignorePath);

    if (gitignoreExists) {
      try {
        existingContent = fs.readFileSync(gitignorePath, "utf-8");
      } catch (err) {
        return {
          success: false,
          addedEntries: [],
          alreadyPresent: [],
          error: `Cannot read .gitignore: ${String(err)}`,
        };
      }
    }

    const existingLines = new Set(
      existingContent
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length > 0 && !l.startsWith("#")),
    );

    const toAdd: string[] = [];
    const alreadyPresent: string[] = [];

    for (const entry of entriesToEnsure) {
      if (existingLines.has(entry)) {
        alreadyPresent.push(entry);
      } else {
        toAdd.push(entry);
      }
    }

    if (toAdd.length === 0) {
      return {
        success: true,
        addedEntries: [],
        alreadyPresent,
      };
    }

    // Build new section
    const timestamp = new Date().toISOString().split("T")[0] ?? "";
    const newSection = [
      "",
      `${GitignoreUpdater.SECURESHIELD_SECTION_HEADER} (${timestamp})`,
      ...toAdd,
      "",
    ].join("\n");

    const newContent = existingContent + newSection;

    try {
      fs.writeFileSync(gitignorePath, newContent, "utf-8");
    } catch (err) {
      return {
        success: false,
        addedEntries: [],
        alreadyPresent,
        error: `Cannot write .gitignore: ${String(err)}`,
      };
    }

    return {
      success: true,
      addedEntries: toAdd,
      alreadyPresent,
    };
  }

  /**
   * Returns the standard entries that SecureShield recommends.
   */
  public static getRecommendedEntries(): string[] {
    return [
      ".env",
      ".env.local",
      ".env.*.local",
      ".env.production",
      ".env.staging",
      ".env.development",
      "*.pem",
      "*.key",
      "*.p12",
      "*.pfx",
      "secrets.json",
      "credentials.json",
      "service-account.json",
      ".netrc",
    ];
  }
}
