import * as vscode from "vscode";
import { SeverityLevel } from "../../core/types/SeverityLevel.js";

/**
 * StatusBarManager — Manages the SecureShield status bar item.
 *
 * States:
 * - Idle:      $(shield) SecureShield
 * - Scanning:  $(loading~spin) Scanning...
 * - Clean:     $(check) No Secrets
 * - Found:     $(error) 3 Secrets (critical)
 * - Error:     $(warning) SecureShield Error
 */
export class StatusBarManager {
  private readonly statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Left,
      100,
    );
    this.statusBarItem.command = "keymontr.openDashboard";
    this.showIdle();
    this.statusBarItem.show();
  }

  public showIdle(): void {
    this.statusBarItem.text = "$(shield) SecureShield";
    this.statusBarItem.tooltip = "SecureShield — Click to open dashboard";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showScanning(): void {
    this.statusBarItem.text = "$(loading~spin) SecureShield: Scanning...";
    this.statusBarItem.tooltip = "SecureShield is scanning for secrets...";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showClean(): void {
    this.statusBarItem.text = "$(check) SecureShield: Clean";
    this.statusBarItem.tooltip = "SecureShield: No secrets detected";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showFindings(count: number, highestSeverity: SeverityLevel): void {
    const icon = this.getSeverityIcon(highestSeverity);
    const label = count === 1 ? "1 Secret" : `${count} Secrets`;

    this.statusBarItem.text = `${icon} SecureShield: ${label}`;
    this.statusBarItem.tooltip = `SecureShield: ${label} detected (${highestSeverity})\nClick to open dashboard`;

    if (
      highestSeverity === SeverityLevel.CRITICAL ||
      highestSeverity === SeverityLevel.HIGH
    ) {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.errorBackground",
      );
    } else if (highestSeverity === SeverityLevel.MEDIUM) {
      this.statusBarItem.backgroundColor = new vscode.ThemeColor(
        "statusBarItem.warningBackground",
      );
    } else {
      this.statusBarItem.backgroundColor = undefined;
    }
  }

  public showError(message: string): void {
    this.statusBarItem.text = "$(warning) SecureShield: Error";
    this.statusBarItem.tooltip = `SecureShield Error: ${message}`;
    this.statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground",
    );
  }

  public dispose(): void {
    this.statusBarItem.dispose();
  }

  private getSeverityIcon(severity: SeverityLevel): string {
    switch (severity) {
      case SeverityLevel.CRITICAL:
        return "$(error)";
      case SeverityLevel.HIGH:
        return "$(warning)";
      case SeverityLevel.MEDIUM:
        return "$(info)";
      default:
        return "$(circle-outline)";
    }
  }
}
