import * as fs from "fs";
import * as path from "path";
import * as os from "os";

export interface HookInstallResult {
  success: boolean;
  hookPath: string;
  backupPath?: string;
  alreadyInstalled: boolean;
  error?: string;
}

export interface HookRemoveResult {
  success: boolean;
  restored: boolean;
  error?: string;
}

/**
 * GitHookManager — Installs and manages the Git pre-commit hook.
 *
 * Detects whether Husky is in use and integrates appropriately.
 * Backs up any existing pre-commit hook before overwriting.
 * Makes the hook executable on Unix systems.
 */
export class GitHookManager {
  private readonly gitDir: string;
  private readonly hooksDir: string;
  private readonly hookPath: string;
  private readonly backupPath: string;

  constructor(private readonly workspaceRoot: string) {
    this.gitDir = path.join(workspaceRoot, ".git");
    this.hooksDir = path.join(this.gitDir, "hooks");
    this.hookPath = path.join(this.hooksDir, "pre-commit");
    this.backupPath = path.join(
      this.hooksDir,
      "pre-commit.secureshield.backup",
    );
  }

  /**
   * Returns true if the workspace has a .git directory.
   */
  public isGitRepository(): boolean {
    return fs.existsSync(this.gitDir);
  }

  /**
   * Returns true if the pre-commit hook is already installed by SecureShield.
   */
  public isHookInstalled(): boolean {
    if (!fs.existsSync(this.hookPath)) {
      return false;
    }
    try {
      const content = fs.readFileSync(this.hookPath, "utf-8");
      return content.includes("SECURESHIELD_HOOK");
    } catch {
      return false;
    }
  }

  /**
   * Detects if Husky is present in the project.
   */
  public isHuskyPresent(): boolean {
    const huskyDir = path.join(this.workspaceRoot, ".husky");
    const huskyPkg = path.join(
      this.workspaceRoot,
      "node_modules",
      "husky",
      "package.json",
    );
    return fs.existsSync(huskyDir) || fs.existsSync(huskyPkg);
  }

  /**
   * Installs the pre-commit hook.
   *
   * If Husky is detected, installs to .husky/pre-commit instead.
   * Backs up any existing hook first.
   */
  public install(extensionPath: string): HookInstallResult {
    if (!this.isGitRepository()) {
      return {
        success: false,
        hookPath: this.hookPath,
        alreadyInstalled: false,
        error: "Not a Git repository",
      };
    }

    if (this.isHookInstalled()) {
      return {
        success: true,
        hookPath: this.hookPath,
        alreadyInstalled: true,
      };
    }

    // Husky integration
    if (this.isHuskyPresent()) {
      return this.installForHusky(extensionPath);
    }

    return this.installDirectHook(extensionPath);
  }

  /**
   * Installs directly into .git/hooks/pre-commit.
   */
  private installDirectHook(extensionPath: string): HookInstallResult {
    // Ensure hooks directory exists
    if (!fs.existsSync(this.hooksDir)) {
      try {
        fs.mkdirSync(this.hooksDir, { recursive: true });
      } catch (err) {
        return {
          success: false,
          hookPath: this.hookPath,
          alreadyInstalled: false,
          error: `Cannot create hooks directory: ${String(err)}`,
        };
      }
    }

    // Backup existing hook
    let backupPath: string | undefined;
    if (fs.existsSync(this.hookPath)) {
      try {
        fs.copyFileSync(this.hookPath, this.backupPath);
        backupPath = this.backupPath;
      } catch {
        // Non-fatal — proceed without backup
      }
    }

    const hookContent = this.buildHookScript(extensionPath);

    try {
      fs.writeFileSync(this.hookPath, hookContent, "utf-8");
    } catch (err) {
      return {
        success: false,
        hookPath: this.hookPath,
        alreadyInstalled: false,
        error: `Cannot write hook: ${String(err)}`,
      };
    }

    // Make executable on Unix
    if (os.platform() !== "win32") {
      try {
        fs.chmodSync(this.hookPath, 0o755);
      } catch {
        // Non-fatal on some systems
      }
    }

    return {
      success: true,
      hookPath: this.hookPath,
      ...(backupPath !== undefined ? { backupPath } : {}),
      alreadyInstalled: false,
    };
  }

  /**
   * Integrates with Husky by adding to .husky/pre-commit.
   */
  private installForHusky(extensionPath: string): HookInstallResult {
    const huskyHookPath = path.join(this.workspaceRoot, ".husky", "pre-commit");

    const huskyDir = path.join(this.workspaceRoot, ".husky");
    if (!fs.existsSync(huskyDir)) {
      try {
        fs.mkdirSync(huskyDir, { recursive: true });
      } catch (err) {
        return {
          success: false,
          hookPath: huskyHookPath,
          alreadyInstalled: false,
          error: `Cannot create .husky directory: ${String(err)}`,
        };
      }
    }

    let existingContent: string;
    if (fs.existsSync(huskyHookPath)) {
      try {
        existingContent = fs.readFileSync(huskyHookPath, "utf-8");
        if (existingContent.includes("SECURESHIELD_HOOK")) {
          return {
            success: true,
            hookPath: huskyHookPath,
            alreadyInstalled: true,
          };
        }
      } catch {
        existingContent = "#!/bin/sh\n";
      }
    } else {
      existingContent = "#!/bin/sh\n";
    }

    const secureShieldLine = this.buildHuskyLine(extensionPath);
    const newContent = `${existingContent}\n# SECURESHIELD_HOOK\n${secureShieldLine}\n`;

    try {
      fs.writeFileSync(huskyHookPath, newContent, "utf-8");
      if (os.platform() !== "win32") {
        fs.chmodSync(huskyHookPath, 0o755);
      }
    } catch (err) {
      return {
        success: false,
        hookPath: huskyHookPath,
        alreadyInstalled: false,
        error: `Cannot update Husky hook: ${String(err)}`,
      };
    }

    return {
      success: true,
      hookPath: huskyHookPath,
      alreadyInstalled: false,
    };
  }

  /**
   * Removes the SecureShield pre-commit hook.
   * Restores any backup if it exists.
   */
  public remove(): HookRemoveResult {
    if (!fs.existsSync(this.hookPath)) {
      return { success: true, restored: false };
    }

    try {
      // Check if it's ours
      const content = fs.readFileSync(this.hookPath, "utf-8");
      if (!content.includes("SECURESHIELD_HOOK")) {
        return {
          success: false,
          restored: false,
          error: "Hook not installed by SecureShield — will not remove",
        };
      }

      fs.unlinkSync(this.hookPath);

      // Restore backup if it exists
      if (fs.existsSync(this.backupPath)) {
        fs.copyFileSync(this.backupPath, this.hookPath);
        fs.unlinkSync(this.backupPath);
        return { success: true, restored: true };
      }

      return { success: true, restored: false };
    } catch (err) {
      return {
        success: false,
        restored: false,
        error: `Cannot remove hook: ${String(err)}`,
      };
    }
  }

  /**
   * Builds the hook script content.
   */
  private buildHookScript(extensionPath: string): string {
    const nodeExecPath = process.execPath;
    const scannerScript = path.join(
      extensionPath,
      "dist",
      "precommit-scanner.js",
    );

    return `#!/bin/sh
# SECURESHIELD_HOOK — Managed by SecureShield VS Code Extension
# Do not edit this section manually. Use the SecureShield extension to manage.
# Version: 1.0.0

echo "SecureShield: Scanning staged files for secrets..."

# Run the SecureShield pre-commit scanner
"${nodeExecPath}" "${scannerScript}" --staged

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "██████████████████████████████████████████"
  echo "  SECURESHIELD: SECRET DETECTED"
  echo "  Commit has been BLOCKED."
  echo "  Fix the issues above or run:"
  echo "  git commit --no-verify  (bypass, not recommended)"
  echo "██████████████████████████████████████████"
  echo ""
  exit 1
fi

echo "SecureShield: No secrets detected. Commit allowed."
exit 0
`;
  }

  /**
   * Builds a single line for Husky integration.
   */
  private buildHuskyLine(extensionPath: string): string {
    const nodeExecPath = process.execPath;
    const scannerScript = path.join(
      extensionPath,
      "dist",
      "precommit-scanner.js",
    );
    return `"${nodeExecPath}" "${scannerScript}" --staged`;
  }
}
