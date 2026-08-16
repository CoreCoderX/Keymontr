import * as vscode from "vscode";
import { SecretFinding } from "../../core/types/SecretFinding.js";
import { RemediationOrchestrator } from "../../remediation/RemediationOrchestrator.js";
import { DeveloperMemoryStore } from "../../storage/DeveloperMemoryStore.js";
import { SecretHistoryStore } from "../../storage/SecretHistoryStore.js";
import { GitHookManager } from "../../git/GitHookManager.js";
import { SecureShieldTreeDataProvider } from "../providers/TreeDataProvider.js";
import { SecureShieldDecorationProvider } from "../providers/DecorationProvider.js";
import { DiagnosticProvider } from "../providers/DiagnosticProvider.js";
import { Gate8_DeveloperMemory } from "../../core/pipeline/Gate8_DeveloperMemory.js";
import { SecureShieldConfig } from "../../config/ConfigurationManager.js";

/**
 * CommandRegistry — Registers all VS Code commands for SecureShield.
 *
 * All command handlers are defined here for centralized management.
 * Each command is pushed to context.subscriptions for automatic cleanup.
 */
export class CommandRegistry {
  constructor(
    private readonly context: vscode.ExtensionContext,
    private readonly orchestrator: RemediationOrchestrator,
    private readonly memoryStore: DeveloperMemoryStore,
    private readonly historyStore: SecretHistoryStore,
    private readonly gitHookManager: GitHookManager,
    private readonly treeProvider: SecureShieldTreeDataProvider,
    private readonly diagnosticProvider: DiagnosticProvider,
    private readonly decorationProvider: SecureShieldDecorationProvider,
    private readonly gate8: Gate8_DeveloperMemory,
    private readonly config: SecureShieldConfig,
    private readonly workspaceRoot: string,
  ) {}

  /**
   * Registers all commands with VS Code.
   */
  public registerAll(): void {
    this.register("keymontr.fixSecret", this.onFixSecret.bind(this));
    this.register("keymontr.markAsSafe", this.onMarkAsSafe.bind(this));
    this.register("keymontr.ignoreOnce", this.onIgnoreOnce.bind(this));
    this.register(
      "keymontr.openDashboard",
      this.onOpenDashboard.bind(this),
    );
    this.register("keymontr.exportReport", this.onExportReport.bind(this));
    this.register(
      "keymontr.installGitHook",
      this.onInstallGitHook.bind(this),
    );
    this.register(
      "keymontr.removeGitHook",
      this.onRemoveGitHook.bind(this),
    );
    this.register("keymontr.clearHistory", this.onClearHistory.bind(this));
    this.register(
      "keymontr.scanWorkspace",
      this.onScanWorkspace.bind(this),
    );
  }

  private register<Args extends unknown[]>(
    command: string,
    handler: (...args: Args) => unknown,
  ): void {
    const disposable = vscode.commands.registerCommand(command, handler);
    this.context.subscriptions.push(disposable);
  }

  // ── Command Handlers ──────────────────────────────────────────────────────

  private async onFixSecret(finding?: SecretFinding): Promise<void> {
    if (finding === undefined) {
      await vscode.window.showErrorMessage(
        "SecureShield: No finding provided to fix",
      );
      return;
    }

    const editor = vscode.window.activeTextEditor;
    const languageId = editor?.document.languageId ?? "typescript";

    const outcome = await this.orchestrator.remediate(
      finding,
      languageId,
      this.config.remediation.autoCreateEnvFile,
      this.config.remediation.autoUpdateGitignore,
      this.config.remediation.autoCreateEnvExample,
    );

    // The secret now lives in .env, which is git-ignored. Clear any markers
    // that were left on it from before the fix so it stops being flagged.
    if (outcome.envFilePath !== undefined) {
      this.diagnosticProvider.clearFile(vscode.Uri.file(outcome.envFilePath));
      this.decorationProvider.setFileRisk(outcome.envFilePath, null);
      this.treeProvider.updateFindings(outcome.envFilePath, []);
    }
  }

  private async onMarkAsSafe(finding?: SecretFinding): Promise<void> {
    if (finding === undefined) {
      return;
    }

    const reason = await vscode.window.showInputBox({
      prompt: "Why is this safe? (optional — helps audit trail)",
      placeHolder: "e.g., Test fixture, public key, example value",
      ignoreFocusOut: true,
    });

    await this.memoryStore.addPermanentSuppression(
      finding.meta.fileUri,
      finding.candidate.lineNumber,
      finding.candidate.line,
      finding.severity,
      finding.detection.matchedRuleId,
      reason,
    );

    await this.historyStore.recordSuppression();

    // Clear the diagnostic for this finding
    this.diagnosticProvider.clearFile(vscode.Uri.file(finding.meta.fileUri));

    await vscode.window.showInformationMessage(
      `SecureShield: Finding marked as safe and permanently suppressed.`,
    );
  }

  private onIgnoreOnce(finding?: SecretFinding): void {
    if (finding === undefined) {
      return;
    }

    this.gate8.suppressForSession(
      finding.meta.fileUri,
      finding.candidate.lineNumber,
      finding.candidate.line,
      finding.detection.matchedRuleId,
    );

    this.diagnosticProvider.clearFile(vscode.Uri.file(finding.meta.fileUri));
  }

  private async onOpenDashboard(): Promise<void> {
    await vscode.commands.executeCommand(
      "workbench.view.extension.keymontr-sidebar",
    );
  }

  private async onExportReport(): Promise<void> {
    const history = this.historyStore.getHistory();
    const stats = this.historyStore.getStatistics();
    const suppressions = this.memoryStore.getAllSuppressions();

    const report = {
      generatedAt: new Date().toISOString(),
      statistics: stats,
      history: history.slice(0, 100), // Last 100 entries
      suppressions: suppressions.map((s) => ({
        fileUri: s.fileUri,
        severity: s.severity,
        suppressedAt: s.suppressedAt,
        reason: s.reason,
      })),
    };

    const saveUri = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.file(
        `${this.workspaceRoot}/secureshield-report-${Date.now()}.json`,
      ),
      filters: { "JSON Report": ["json"] },
    });

    if (saveUri !== undefined) {
      const content = JSON.stringify(report, null, 2);
      await vscode.workspace.fs.writeFile(
        saveUri,
        Buffer.from(content, "utf-8"),
      );
      await vscode.window.showInformationMessage(
        `SecureShield: Report exported to ${saveUri.fsPath}`,
      );
    }
  }

  private async onInstallGitHook(): Promise<void> {
    if (!this.gitHookManager.isGitRepository()) {
      await vscode.window.showErrorMessage(
        "SecureShield: No Git repository found in workspace",
      );
      return;
    }

    const result = this.gitHookManager.install(
      this.context.extensionPath,
    );

    if (result.success) {
      if (result.alreadyInstalled) {
        await vscode.window.showInformationMessage(
          "SecureShield: Git pre-commit hook is already installed.",
        );
      } else {
        await vscode.window.showInformationMessage(
          `SecureShield: Git pre-commit hook installed at ${result.hookPath}`,
        );
      }
    } else {
      await vscode.window.showErrorMessage(
        `SecureShield: Failed to install hook — ${result.error ?? "unknown error"}`,
      );
    }
  }

  private async onRemoveGitHook(): Promise<void> {
    const confirm = await vscode.window.showWarningMessage(
      "Remove SecureShield Git pre-commit hook?",
      { modal: true },
      "Remove",
    );

    if (confirm !== "Remove") {
      return;
    }

    const result = this.gitHookManager.remove();

    if (result.success) {
      const detail = result.restored
        ? "Previous hook restored."
        : "Hook removed.";
      await vscode.window.showInformationMessage(
        `SecureShield: Git hook removed. ${detail}`,
      );
    } else {
      await vscode.window.showErrorMessage(
        `SecureShield: ${result.error ?? "Failed to remove hook"}`,
      );
    }
  }

  private async onClearHistory(): Promise<void> {
    const confirm = await vscode.window.showWarningMessage(
      "Clear all SecureShield detection history and statistics?",
      { modal: true },
      "Clear All",
    );

    if (confirm !== "Clear All") {
      return;
    }

    await this.historyStore.clearAll();
    this.treeProvider.clearAll();
    this.diagnosticProvider.clearAll();

    await vscode.window.showInformationMessage(
      "SecureShield: History and statistics cleared.",
    );
  }

  private async onScanWorkspace(): Promise<void> {
    await vscode.window.showInformationMessage(
      "SecureShield: Workspace scan started. Results will appear in the sidebar.",
    );
    await vscode.commands.executeCommand("keymontr.internalFullScan");
  }
}
