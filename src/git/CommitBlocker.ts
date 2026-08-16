import { PreCommitScanResult } from "./PreCommitScanner.js";

/**
 * CommitBlocker — Formats the CLI output when a commit is blocked.
 *
 * Produces a clear, readable error message that shows:
 * - Which files contain secrets
 * - What type of secret was found
 * - What severity level
 * - How to fix it
 */
export class CommitBlocker {
  /**
   * Formats and prints the block message to stderr.
   * Returns the exit code (1 = blocked, 0 = allowed).
   */
  public formatBlockMessage(result: PreCommitScanResult): string {
    if (!result.blocked || result.findings.length === 0) {
      return this.formatSuccessMessage(result.scannedFiles);
    }

    const lines: string[] = [];
    const border = "═".repeat(60);
    const thinBorder = "─".repeat(60);

    lines.push("");
    lines.push(`╔${border}╗`);
    lines.push(`║${"  SECURESHIELD — SECRET DETECTION ALERT".padEnd(60)}║`);
    lines.push(`╠${border}╣`);
    lines.push(
      `║${"  Commit BLOCKED — secrets detected in staged files".padEnd(60)}║`,
    );
    lines.push(`╚${border}╝`);
    lines.push("");

    // Group findings by file
    const byFile = new Map<string, typeof result.findings>();
    for (const finding of result.findings) {
      const existing = byFile.get(finding.file) ?? [];
      existing.push(finding);
      byFile.set(finding.file, existing);
    }

    for (const [file, findings] of byFile) {
      lines.push(`  ${file}`);
      lines.push(`  ${thinBorder}`);

      for (const finding of findings) {
        const conf = `${(finding.confidence * 100).toFixed(0)}%`;
        lines.push(`  • Line ${finding.line}: ${finding.description}`);
        lines.push(
          `     Severity: ${finding.severity.toUpperCase()}  |  Confidence: ${conf}`,
        );
      }
      lines.push("");
    }

    lines.push(`  ${thinBorder}`);
    lines.push("  HOW TO FIX:");
    lines.push("  1. Open VS Code — SecureShield will highlight the issues");
    lines.push('  2. Click "Fix Now" to auto-move secrets to .env');
    lines.push("  3. Commit again after fixing");
    lines.push("");
    lines.push("  TO BYPASS (not recommended):");
    lines.push("  git commit --no-verify");
    lines.push("");
    lines.push(`  Scanned ${result.scannedFiles} file(s)`);
    lines.push(`╔${border}╗`);
    lines.push(
      `║${"  SecureShield  •  Protecting your repository".padEnd(60)}║`,
    );
    lines.push(`╚${border}╝`);
    lines.push("");

    return lines.join("\n");
  }

  private formatSuccessMessage(scannedFiles: number): string {
    return `SecureShield: No secrets found in ${scannedFiles} staged file(s). Commit allowed.\n`;
  }
}
