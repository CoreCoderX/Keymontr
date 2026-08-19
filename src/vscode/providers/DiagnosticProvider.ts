import * as vscode from "vscode";
import { SecretFinding } from "../../core/types/SecretFinding.js";
import { SeverityLevel } from "../../core/types/SeverityLevel.js";
import { PipelineResult } from "../../core/types/SecretFinding.js";

/**
 * DiagnosticProvider — Renders VS Code diagnostics (squiggly underlines)
 * for detected secrets.
 *
 * Maps Keymontr severity levels to VS Code DiagnosticSeverity.
 * Maintains a DiagnosticCollection that VS Code reads from.
 */
export class DiagnosticProvider {
  private readonly diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection =
      vscode.languages.createDiagnosticCollection("keymontr");
  }

  /**
   * Updates diagnostics for a file based on pipeline results.
   *
   * @param fileUri - VS Code URI of the file
   * @param pipelineResult - Results from the detection pipeline
   */
  public update(fileUri: vscode.Uri, pipelineResult: PipelineResult): void {
    if (pipelineResult.findings.length === 0) {
      this.diagnosticCollection.set(fileUri, []);
      return;
    }

    const diagnostics = pipelineResult.findings.map((finding) =>
      this.buildDiagnostic(finding),
    );

    this.diagnosticCollection.set(fileUri, diagnostics);
  }

  /**
   * Clears diagnostics for a specific file.
   */
  public clearFile(fileUri: vscode.Uri): void {
    this.diagnosticCollection.set(fileUri, []);
  }

  /**
   * Clears all diagnostics across all files.
   */
  public clearAll(): void {
    this.diagnosticCollection.clear();
  }

  /**
   * Disposes the diagnostic collection.
   */
  public dispose(): void {
    this.diagnosticCollection.dispose();
  }

  /**
   * Builds a single VS Code diagnostic from a SecretFinding.
   */
  private buildDiagnostic(finding: SecretFinding): vscode.Diagnostic {
    const range = new vscode.Range(
      new vscode.Position(
        finding.candidate.lineNumber,
        Math.max(0, finding.candidate.startChar - 1),
      ),
      new vscode.Position(
        finding.candidate.lineNumber,
        finding.candidate.endChar + 1,
      ),
    );

    const severity = this.mapSeverity(finding.severity);
    const confidencePct = (finding.confidence.finalScore * 100).toFixed(0);

    const message = this.buildMessage(finding, confidencePct);

    const diagnostic = new vscode.Diagnostic(range, message, severity);
    diagnostic.source = "Keymontr";
    diagnostic.code = {
      value: finding.detection.matchedRuleId ?? "generic-secret",
      target: vscode.Uri.parse(
        "https://github.com/CoreCoderX/Keymontr#readme",
      ),
    };

    return diagnostic;
  }

  /**
   * Builds a human-readable diagnostic message.
   */
  private buildMessage(finding: SecretFinding, confidencePct: string): string {
    const parts: string[] = [];

    parts.push(`Keymontr:`);

    if (finding.detection.matchedRuleName !== undefined) {
      parts.push(finding.detection.matchedRuleName);
    } else if (finding.detection.matchedGroup !== undefined) {
      parts.push(`Possible ${finding.detection.matchedGroup} credential`);
    } else {
      parts.push("Potential secret detected");
    }

    parts.push(
      `[${finding.severity.toUpperCase()} — ${confidencePct}% confidence]`,
    );
    parts.push(
      `→ Move to .env: process.env.${finding.remediation.suggestedEnvKey}`,
    );

    return parts.join(" ");
  }

  /**
   * Maps Keymontr severity to VS Code DiagnosticSeverity.
   */
  private mapSeverity(severity: SeverityLevel): vscode.DiagnosticSeverity {
    switch (severity) {
      case SeverityLevel.CRITICAL:
      case SeverityLevel.HIGH:
        return vscode.DiagnosticSeverity.Error;
      case SeverityLevel.MEDIUM:
        return vscode.DiagnosticSeverity.Warning;
      case SeverityLevel.LOW:
        return vscode.DiagnosticSeverity.Information;
      case SeverityLevel.INFORMATIONAL:
        return vscode.DiagnosticSeverity.Hint;
      default:
        return vscode.DiagnosticSeverity.Warning;
    }
  }
}
