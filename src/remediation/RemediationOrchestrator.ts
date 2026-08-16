import * as vscode from "vscode";
import { EnvFileMigrator } from "./EnvFileMigrator.js";
import { GitignoreUpdater } from "./GitignoreUpdater.js";
import { CodeReplacer } from "./CodeReplacer.js";
import { EnvExampleGenerator } from "./EnvExampleGenerator.js";
import { SecretFinding } from "../core/types/SecretFinding.js";
import { SecretHistoryStore } from "../storage/SecretHistoryStore.js";

export interface RemediationOutcome {
  success: boolean;
  steps: RemediationStep[];
  error?: string;
  /** Absolute path of the .env file the secret was migrated to (if any). */
  envFilePath?: string;
}

export interface RemediationStep {
  name: string;
  success: boolean;
  detail: string;
}

/**
 * RemediationOrchestrator — Coordinates the full auto-fix workflow.
 *
 * When a developer clicks "Fix Now" or triggers auto-fix, this class
 * executes all remediation steps in the correct order:
 *
 * Step 1: Migrate secret to .env
 * Step 2: Replace hardcoded value with process.env reference
 * Step 3: Update .gitignore
 * Step 4: Update .env.example with placeholder
 */
export class RemediationOrchestrator {
  private readonly migrator: EnvFileMigrator;
  private readonly gitignoreUpdater: GitignoreUpdater;
  private readonly codeReplacer: CodeReplacer;
  private readonly envExampleGenerator: EnvExampleGenerator;

  constructor(
    workspaceRoot: string,
    private readonly historyStore: SecretHistoryStore,
    preferredEnvFileName: string = ".env",
  ) {
    this.migrator = new EnvFileMigrator(workspaceRoot, preferredEnvFileName);
    this.gitignoreUpdater = new GitignoreUpdater(workspaceRoot);
    this.codeReplacer = new CodeReplacer();
    this.envExampleGenerator = new EnvExampleGenerator(workspaceRoot);
  }

  /**
   * Executes the full remediation workflow for a given finding.
   *
   * @param finding - The secret finding to remediate
   * @param languageId - Language identifier for code replacement syntax
   * @param autoCreateEnvFile - Whether to auto-create the .env file
   * @param autoUpdateGitignore - Whether to update .gitignore
   * @param autoCreateEnvExample - Whether to update .env.example
   */
  public async remediate(
    finding: SecretFinding,
    languageId: string,
    autoCreateEnvFile = true,
    autoUpdateGitignore = true,
    autoCreateEnvExample = true,
  ): Promise<RemediationOutcome> {
    const steps: RemediationStep[] = [];
    let envFilePath: string | undefined;

    // ── Step 1: Migrate to .env ────────────────────────────────────────────
    if (autoCreateEnvFile) {
      const migrationResult = this.migrator.migrate(finding);
      steps.push({
        name: "Migrate to .env",
        success: migrationResult.success,
        detail: migrationResult.success
          ? migrationResult.envValueUpdated === true
            ? `Updated ${migrationResult.envKey} in ${migrationResult.envFilePath}`
            : `Added ${migrationResult.envKey} to ${migrationResult.envFilePath}`
          : (migrationResult.error ?? "Unknown error"),
      });

      if (!migrationResult.success) {
        return {
          success: false,
          steps,
          error: `Migration failed: ${migrationResult.error ?? "unknown"}`,
        };
      }

      envFilePath = migrationResult.envFilePath;
    }

    // ── Step 2: Replace in code ────────────────────────────────────────────
    const replaceResult = await this.codeReplacer.replace(finding, languageId);
    steps.push({
      name: "Replace in source code",
      success: replaceResult.success,
      detail: replaceResult.success
        ? `Replaced with: ${replaceResult.replacementCode}`
        : (replaceResult.error ?? "Unknown error"),
    });

    // ── Step 3: Update .gitignore ──────────────────────────────────────────
    if (autoUpdateGitignore) {
      const gitignoreResult = this.gitignoreUpdater.ensureEntries(
        GitignoreUpdater.getRecommendedEntries(),
      );
      steps.push({
        name: "Update .gitignore",
        success: gitignoreResult.success,
        detail: gitignoreResult.success
          ? gitignoreResult.addedEntries.length > 0
            ? `Added: ${gitignoreResult.addedEntries.join(", ")}`
            : "All entries already present"
          : (gitignoreResult.error ?? "Unknown error"),
      });
    }

    // ── Step 4: Update .env.example ───────────────────────────────────────
    if (autoCreateEnvExample) {
      const exampleResult = this.envExampleGenerator.addKey(
        finding.remediation.suggestedEnvKey,
        `Secret detected by SecureShield: ${finding.detection.matchedRuleName ?? finding.detection.matchedGroup ?? "unknown type"}`,
      );
      steps.push({
        name: "Update .env.example",
        success: exampleResult.success,
        detail: exampleResult.success
          ? exampleResult.addedKeys.length > 0
            ? `Added placeholder for ${finding.remediation.suggestedEnvKey}`
            : "Key already in .env.example"
          : (exampleResult.error ?? "Unknown error"),
      });
    }

    // ── Mark as fixed in history ───────────────────────────────────────────
    await this.historyStore.markFixed(finding.id);

    const allSuccess = steps.every((s) => s.success);

    if (allSuccess) {
      await vscode.window.showInformationMessage(
        `SecureShield: Secret fixed! Moved to .env and code updated.`,
      );
    } else {
      const failed = steps.filter((s) => !s.success).map((s) => s.name);
      await vscode.window.showWarningMessage(
        `SecureShield: Partial fix applied. Failed steps: ${failed.join(", ")}`,
      );
    }

    return { success: allSuccess, steps, ...(envFilePath !== undefined ? { envFilePath } : {}) };
  }
}
