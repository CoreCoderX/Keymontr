import * as vscode from "vscode";
import { SecretFinding } from "../core/types/SecretFinding.js";

export interface CodeReplaceResult {
  success: boolean;
  replacedValue: string;
  replacementCode: string;
  error?: string;
}

/**
 * CodeReplacer — Replaces a hardcoded secret in source code
 * with a process.env reference (or language-appropriate equivalent).
 *
 * Supports:
 * - JavaScript / TypeScript: process.env.KEY
 * - Python: os.environ.get("KEY")
 * - Go: os.Getenv("KEY")
 * - Ruby: ENV["KEY"]
 * - PHP: $_ENV["KEY"] or getenv("KEY")
 * - Generic: process.env.KEY (fallback)
 */
export class CodeReplacer {
  /**
   * Applies a workspace edit to replace the hardcoded secret in the editor.
   *
   * @param finding - The secret finding to replace
   * @param languageId - The VS Code language identifier of the file
   */
  public async replace(
    finding: SecretFinding,
    languageId: string,
  ): Promise<CodeReplaceResult> {
    const envKey = finding.remediation.suggestedEnvKey;
    const originalValue = finding.candidate.value;

    if (!envKey || envKey.length === 0) {
      return {
        success: false,
        replacedValue: originalValue,
        replacementCode: "",
        error: "No environment variable key available",
      };
    }

    const replacement = this.buildReplacement(envKey, languageId);

    const fileUri = vscode.Uri.file(finding.meta.fileUri);

    // Build position — VS Code uses 0-based line and character
    const line = finding.candidate.lineNumber;

    // We need to find the exact range of the quoted string literal
    // startChar and endChar point to the content inside quotes
    // We need to include the surrounding quotes in the replacement
    const startChar = finding.candidate.startChar - 1; // Include opening quote
    const endChar = finding.candidate.endChar + 1; // Include closing quote

    const range = new vscode.Range(
      new vscode.Position(line, Math.max(0, startChar)),
      new vscode.Position(line, endChar),
    );

    const edit = new vscode.WorkspaceEdit();
    edit.replace(fileUri, range, replacement);

    try {
      const applied = await vscode.workspace.applyEdit(edit);
      if (!applied) {
        return {
          success: false,
          replacedValue: originalValue,
          replacementCode: replacement,
          error: "VS Code failed to apply the workspace edit",
        };
      }

      return {
        success: true,
        replacedValue: originalValue,
        replacementCode: replacement,
      };
    } catch (err) {
      return {
        success: false,
        replacedValue: originalValue,
        replacementCode: replacement,
        error: `Edit failed: ${String(err)}`,
      };
    }
  }

  /**
   * Builds the language-appropriate replacement expression.
   */
  public buildReplacement(envKey: string, languageId: string): string {
    switch (languageId.toLowerCase()) {
      case "python":
        return `os.environ.get("${envKey}")`;

      case "go":
        return `os.Getenv("${envKey}")`;

      case "ruby":
        return `ENV["${envKey}"]`;

      case "php":
        return `getenv("${envKey}")`;

      case "rust":
        return `std::env::var("${envKey}").unwrap()`;

      case "java":
        return `System.getenv("${envKey}")`;

      case "csharp":
        return `Environment.GetEnvironmentVariable("${envKey}")`;

      case "javascript":
      case "typescript":
      case "javascriptreact":
      case "typescriptreact":
      default:
        return `process.env.${envKey}`;
    }
  }

  /**
   * Previews what the replacement would look like without applying it.
   */
  public previewReplacement(
    finding: SecretFinding,
    languageId: string,
  ): string {
    return this.buildReplacement(
      finding.remediation.suggestedEnvKey,
      languageId,
    );
  }
}
