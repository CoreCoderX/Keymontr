import * as vscode from "vscode";
import { SecretFinding } from "../../core/types/SecretFinding.js";

/**
 * CodeActionProvider — Provides Quick Fix actions for secret diagnostics.
 *
 * When the developer clicks the lightbulb icon or presses Ctrl+. on a
 * SecureShield diagnostic, these actions are shown:
 *
 * 1. Fix Now — move to .env and replace in code
 * 2. Mark as Safe — permanently suppress this finding
 * 3. Ignore Once — suppress for this session only
 * 4. View Details — show finding details in dashboard
 */
export class SecureShieldCodeActionProvider
  implements vscode.CodeActionProvider
{
  // Map from diagnostic message fingerprint to finding ID
  private findingMap: Map<string, SecretFinding> = new Map();

  /**
   * Called by VS Code when quick fixes are needed for a range.
   */
  public provideCodeActions(
    document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    const secureshieldDiagnostics = context.diagnostics.filter(
      (d) => d.source === "SecureShield",
    );

    if (secureshieldDiagnostics.length === 0) {
      return [];
    }

    for (const diagnostic of secureshieldDiagnostics) {
      // Find the matching SecretFinding
      const finding = this.findFindingForDiagnostic(document, diagnostic);

      if (finding !== undefined) {
        actions.push(this.buildFixNowAction(diagnostic, finding, document));
        actions.push(this.buildMarkSafeAction(diagnostic, finding));
        actions.push(this.buildIgnoreOnceAction(diagnostic, finding));
        actions.push(this.buildOpenDashboardAction());
      } else {
        // Fallback actions when finding metadata is not available
        actions.push(this.buildOpenDashboardAction());
      }
    }

    return actions;
  }

  /**
   * Registers a finding so code actions can reference it.
   */
  public registerFinding(finding: SecretFinding): void {
    this.findingMap.set(finding.id, finding);
  }

  /**
   * Clears all registered findings (called when file is re-scanned).
   */
  public clearFindingsForFile(fileUri: string): void {
    for (const [key, finding] of this.findingMap) {
      if (finding.meta.fileUri === fileUri) {
        this.findingMap.delete(key);
      }
    }
  }

  private findFindingForDiagnostic(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic,
  ): SecretFinding | undefined {
    // Match by file URI and line number
    const lineNumber = diagnostic.range.start.line;
    for (const finding of this.findingMap.values()) {
      if (
        finding.meta.fileUri === document.uri.fsPath &&
        finding.candidate.lineNumber === lineNumber
      ) {
        return finding;
      }
    }
    return undefined;
  }

  private buildFixNowAction(
    diagnostic: vscode.Diagnostic,
    finding: SecretFinding,
    _document: vscode.TextDocument,
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `SecureShield: Fix — Move to .env (${finding.remediation.suggestedEnvKey})`,
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diagnostic];
    action.isPreferred = true;
    action.command = {
      title: "Fix Secret",
      command: "keymontr.fixSecret",
      arguments: [finding],
    };
    return action;
  }

  private buildMarkSafeAction(
    diagnostic: vscode.Diagnostic,
    finding: SecretFinding,
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `SecureShield: Mark as Safe (suppress permanently)`,
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diagnostic];
    action.command = {
      title: "Mark as Safe",
      command: "keymontr.markAsSafe",
      arguments: [finding],
    };
    return action;
  }

  private buildIgnoreOnceAction(
    diagnostic: vscode.Diagnostic,
    finding: SecretFinding,
  ): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `SecureShield: Ignore for this session`,
      vscode.CodeActionKind.QuickFix,
    );
    action.diagnostics = [diagnostic];
    action.command = {
      title: "Ignore Once",
      command: "keymontr.ignoreOnce",
      arguments: [finding],
    };
    return action;
  }

  private buildOpenDashboardAction(): vscode.CodeAction {
    const action = new vscode.CodeAction(
      `SecureShield: Open Security Dashboard`,
      vscode.CodeActionKind.Empty,
    );
    action.command = {
      title: "Open Dashboard",
      command: "keymontr.openDashboard",
    };
    return action;
  }
}
