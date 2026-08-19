import * as vscode from "vscode";
import { SeverityLevel } from "../../core/types/SeverityLevel.js";

/**
 * StatusBarManager — Manages the Keymontr status bar item.
 *
 * States:
 * - Idle:      $(shield) Keymontr
 * - Scanning:  $(loading~spin) Scanning...
 * - Clean:     $(check) No Secrets
 * - Found:     $(error) 3 Secrets (critical)
 * - Error:     $(warning) Keymontr Error
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
    this.statusBarItem.text = "$(shield) Keymontr";
    this.statusBarItem.tooltip = "Keymontr — Click to open dashboard";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showScanning(): void {
    this.statusBarItem.text = "$(loading~spin) Keymontr: Scanning...";
    this.statusBarItem.tooltip = "Keymontr is scanning for secrets...";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showClean(): void {
    this.statusBarItem.text = "$(check) Keymontr: Clean";
    this.statusBarItem.tooltip = "Keymontr: No secrets detected";
    this.statusBarItem.backgroundColor = undefined;
  }

  public showFindings(count: number, highestSeverity: SeverityLevel): void {
    const icon = this.getSeverityIcon(highestSeverity);
    const label = count === 1 ? "1 Secret" : `${count} Secrets`;

    this.statusBarItem.text = `${icon} Keymontr: ${label}`;
    this.statusBarItem.tooltip = `Keymontr: ${label} detected (${highestSeverity})\nClick to open dashboard`;

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
    this.statusBarItem.text = "$(warning) Keymontr: Error";
    this.statusBarItem.tooltip = `Keymontr Error: ${message}`;
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
