import * as vscode from "vscode";
import { SecretFinding } from "../../core/types/SecretFinding.js";
import { SEVERITY_LABELS } from "../../core/types/SeverityLevel.js";

/**
 * HoverProvider — Shows detailed finding information when the developer
 * hovers over a Keymontr diagnostic.
 *
 * Displays:
 * - Severity and confidence score
 * - Detection method (which layers triggered)
 * - Entropy value
 * - Suggested remediation steps
 * - Quick actions
 */
export class KeymontrHoverProvider implements vscode.HoverProvider {
  private findingMap: Map<string, SecretFinding> = new Map();

  /**
   * Called by VS Code when the user hovers over a position.
   */
  public provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.Hover | undefined {
    const finding = this.findFindingAtPosition(document, position);

    if (finding === undefined) {
      return undefined;
    }

    const content = this.buildHoverContent(finding);
    return new vscode.Hover(content);
  }

  /**
   * Registers a finding for hover display.
   */
  public registerFinding(finding: SecretFinding): void {
    this.findingMap.set(finding.id, finding);
  }

  /**
   * Clears findings for a specific file.
   */
  public clearFindingsForFile(fileUri: string): void {
    for (const [key, finding] of this.findingMap) {
      if (finding.meta.fileUri === fileUri) {
        this.findingMap.delete(key);
      }
    }
  }

  private findFindingAtPosition(
    document: vscode.TextDocument,
    position: vscode.Position
  ): SecretFinding | undefined {
    for (const finding of this.findingMap.values()) {
      if (finding.meta.fileUri !== document.uri.fsPath) {
        continue;
      }
      if (finding.candidate.lineNumber !== position.line) {
        continue;
      }
      const startChar = Math.max(0, finding.candidate.startChar - 1);
      const endChar = finding.candidate.endChar + 1;
      if (position.character >= startChar && position.character <= endChar) {
        return finding;
      }
    }
    return undefined;
  }

  private buildHoverContent(finding: SecretFinding): vscode.MarkdownString {
    const md = new vscode.MarkdownString("", true);
    md.isTrusted = true;

    const label = SEVERITY_LABELS[finding.severity] ?? finding.severity;
    const confidence = (finding.confidence.finalScore * 100).toFixed(1);

    md.appendMarkdown(`### Keymontr — ${label} Risk\n\n`);

    // Detection summary
    md.appendMarkdown(`**Confidence:** ${confidence}%\n\n`);

    if (finding.detection.matchedRuleName !== undefined) {
      md.appendMarkdown(
        `**Type:** ${finding.detection.matchedRuleName}\n\n`
      );
    } else if (finding.detection.matchedGroup !== undefined) {
      md.appendMarkdown(
        `**Category:** ${finding.detection.matchedGroup}\n\n`
      );
    }

    md.appendMarkdown(
      `**Entropy:** ${finding.detection.entropyValue.toFixed(2)}\n\n`
    );

    // Score breakdown
    const c = finding.confidence.components;
    md.appendMarkdown("**Detection Signals:**\n\n");
    md.appendMarkdown("| Layer | Score |\n|---|---|\n");
    md.appendMarkdown(`| Regex Match | ${(c.regex * 100).toFixed(0)}% |\n`);
    md.appendMarkdown(`| Entropy | ${(c.entropy * 100).toFixed(0)}% |\n`);
    md.appendMarkdown(`| Context | ${(c.context * 100).toFixed(0)}% |\n`);
    md.appendMarkdown(`| String Patterns | ${(c.stringGroup * 100).toFixed(0)}% |\n`);
    md.appendMarkdown(`| File Context | ${(c.fileContext * 100).toFixed(0)}% |\n\n`);

    // Remediation
    md.appendMarkdown("**Recommended Fix:**\n\n");
    for (const step of finding.remediation.fixSteps) {
      md.appendMarkdown(`- ${step}\n`);
    }

    md.appendMarkdown("\n\n");
    md.appendMarkdown(
      `[Fix Now](command:keymontr.fixSecret) · ` +
        `[Mark Safe](command:keymontr.markAsSafe) · ` +
        `[Dashboard](command:keymontr.openDashboard)`
    );

    return md;
  }
}