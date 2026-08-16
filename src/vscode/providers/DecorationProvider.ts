import * as vscode from "vscode";
import { SeverityLevel } from "../../core/types/SeverityLevel.js";

/**
 * DecorationProvider — Adds file decorations (risk badges) to the Explorer.
 *
 * Files with detected secrets get a colored badge:
 * CRITICAL/HIGH  →  "!" badge in error/warning color
 * MEDIUM         →  "!" badge in warning color
 * LOW/INFO       →  "•" badge in hint color
 */
export class SecureShieldDecorationProvider
  implements vscode.FileDecorationProvider
{
  private readonly _onDidChangeFileDecorations = new vscode.EventEmitter<
    vscode.Uri | vscode.Uri[] | undefined
  >();

  public readonly onDidChangeFileDecorations =
    this._onDidChangeFileDecorations.event;

  // Map from file URI string → highest severity in that file
  private fileRiskMap: Map<string, SeverityLevel> = new Map();

  /**
   * Called by VS Code to get decoration for a file/folder.
   */
  public provideFileDecoration(
    uri: vscode.Uri,
  ): vscode.FileDecoration | undefined {
    const severity = this.fileRiskMap.get(uri.fsPath);

    if (severity === undefined) {
      return undefined;
    }

    return this.buildDecoration(severity);
  }

  /**
   * Updates the risk level for a file and triggers a UI refresh.
   */
  public setFileRisk(fileUri: string, severity: SeverityLevel | null): void {
    if (severity === null) {
      this.fileRiskMap.delete(fileUri);
    } else {
      this.fileRiskMap.set(fileUri, severity);
    }
    this._onDidChangeFileDecorations.fire(vscode.Uri.file(fileUri));
  }

  /**
   * Clears all decorations.
   */
  public clearAll(): void {
    const uris = Array.from(this.fileRiskMap.keys()).map((p) =>
      vscode.Uri.file(p),
    );
    this.fileRiskMap.clear();
    this._onDidChangeFileDecorations.fire(uris);
  }

  public dispose(): void {
    this._onDidChangeFileDecorations.dispose();
  }

  private buildDecoration(severity: SeverityLevel): vscode.FileDecoration {
    switch (severity) {
      case SeverityLevel.CRITICAL:
        return new vscode.FileDecoration(
          "!",
          "SecureShield: Critical secret detected",
          new vscode.ThemeColor("errorForeground"),
        );
      case SeverityLevel.HIGH:
        return new vscode.FileDecoration(
          "!",
          "SecureShield: High-risk secret detected",
          new vscode.ThemeColor("charts.orange"),
        );
      case SeverityLevel.MEDIUM:
        return new vscode.FileDecoration(
          "!",
          "SecureShield: Medium-risk secret detected",
          new vscode.ThemeColor("editorWarning.foreground"),
        );
      case SeverityLevel.LOW:
      case SeverityLevel.INFORMATIONAL:
        return new vscode.FileDecoration(
          "•",
          "SecureShield: Possible secret — low confidence",
          new vscode.ThemeColor("editorHint.foreground"),
        );
      default:
        return new vscode.FileDecoration(
          "?",
          "SecureShield: Review suggested",
        );
    }
  }
}
