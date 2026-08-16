import * as vscode from "vscode";
import { SecretFinding } from "../../core/types/SecretFinding.js";
import {
  SeverityLevel,
  SEVERITY_THEME_COLORS,
  SEVERITY_LABELS,
} from "../../core/types/SeverityLevel.js";

type TreeItemType = "severity-group" | "finding" | "empty";

interface FindingsTreeItem {
  type: TreeItemType;
  label: string;
  severity?: SeverityLevel;
  finding?: SecretFinding;
  children?: FindingsTreeItem[];
}

/**
 * TreeDataProvider — Populates the SecureShield sidebar tree view.
 *
 * Structure:
 * ├── Critical (2)          ◉ (errorForeground icon)
 * │   ├── config.ts:12 — OpenAI API Key
 * │   └── .env:4 — AWS Access Token
 * ├── High (1)              ◉ (charts.orange icon)
 * │   └── database.js:8 — Generic API Key
 * └── No Issues             ◉ (shield icon)
 */
export class SecureShieldTreeDataProvider implements vscode.TreeDataProvider<FindingsTreeItem> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<
    FindingsTreeItem | undefined | null | void
  >();

  public readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  // All current findings across all files
  private allFindings: Map<string, SecretFinding[]> = new Map();

  /**
   * Updates findings for a specific file and refreshes the tree.
   */
  public updateFindings(fileUri: string, findings: SecretFinding[]): void {
    if (findings.length === 0) {
      this.allFindings.delete(fileUri);
    } else {
      this.allFindings.set(fileUri, findings);
    }
    this._onDidChangeTreeData.fire();
  }

  /**
   * Clears all findings and refreshes the tree.
   */
  public clearAll(): void {
    this.allFindings.clear();
    this._onDidChangeTreeData.fire();
  }

  /**
   * Returns total finding count.
   */
  public get totalCount(): number {
    let count = 0;
    for (const findings of this.allFindings.values()) {
      count += findings.length;
    }
    return count;
  }

  // ── vscode.TreeDataProvider implementation ────────────────────────────────

  public getTreeItem(element: FindingsTreeItem): vscode.TreeItem {
    if (element.type === "severity-group") {
      return this.buildGroupItem(element);
    }
    if (element.type === "finding") {
      return this.buildFindingItem(element);
    }
    return this.buildEmptyItem();
  }

  public getChildren(element?: FindingsTreeItem): FindingsTreeItem[] {
    if (element === undefined) {
      return this.buildRootItems();
    }
    return element.children ?? [];
  }

  // ── Private builders ──────────────────────────────────────────────────────

  private buildRootItems(): FindingsTreeItem[] {
    const allFindings = this.getAllFindingsFlat();

    if (allFindings.length === 0) {
      return [{ type: "empty", label: "No secrets detected" }];
    }

    const grouped = this.groupBySeverity(allFindings);
    const items: FindingsTreeItem[] = [];

    const severityOrder = [
      SeverityLevel.CRITICAL,
      SeverityLevel.HIGH,
      SeverityLevel.MEDIUM,
      SeverityLevel.LOW,
      SeverityLevel.INFORMATIONAL,
    ];

    for (const severity of severityOrder) {
      const findings = grouped.get(severity) ?? [];
      if (findings.length > 0) {
        items.push({
          type: "severity-group",
          label: `${SEVERITY_LABELS[severity]} (${findings.length})`,
          severity,
          children: findings.map((f) => ({
            type: "finding",
            label: `${f.meta.fileName}:${f.candidate.lineNumber + 1}`,
            finding: f,
          })),
        });
      }
    }

    return items;
  }

  private getAllFindingsFlat(): SecretFinding[] {
    const all: SecretFinding[] = [];
    for (const findings of this.allFindings.values()) {
      all.push(...findings);
    }
    return all;
  }

  private groupBySeverity(
    findings: SecretFinding[],
  ): Map<SeverityLevel, SecretFinding[]> {
    const groups = new Map<SeverityLevel, SecretFinding[]>();
    for (const finding of findings) {
      const existing = groups.get(finding.severity) ?? [];
      existing.push(finding);
      groups.set(finding.severity, existing);
    }
    return groups;
  }

  private buildGroupItem(item: FindingsTreeItem): vscode.TreeItem {
    const treeItem = new vscode.TreeItem(
      item.label,
      vscode.TreeItemCollapsibleState.Expanded,
    );
    treeItem.contextValue = "severity-group";

    // Native severity indicator: a filled circle colored by the theme.
    if (item.severity !== undefined) {
      treeItem.iconPath = new vscode.ThemeIcon(
        "circle-filled",
        new vscode.ThemeColor(SEVERITY_THEME_COLORS[item.severity]),
      );
    }

    return treeItem;
  }

  private buildFindingItem(item: FindingsTreeItem): vscode.TreeItem {
    const finding = item.finding;
    if (finding === undefined) {
      return new vscode.TreeItem(item.label);
    }

    const treeItem = new vscode.TreeItem(
      item.label,
      vscode.TreeItemCollapsibleState.None,
    );

    const description =
      finding.detection.matchedRuleName ??
      finding.detection.matchedGroup ??
      "Potential secret";

    treeItem.description = description;
    treeItem.tooltip = new vscode.MarkdownString(
      `**${description}**\n\n` +
        `Confidence: ${(finding.confidence.finalScore * 100).toFixed(0)}%\n\n` +
        `Suggested fix: \`process.env.${finding.remediation.suggestedEnvKey}\``,
    );
    treeItem.command = {
      title: "Go to finding",
      command: "vscode.open",
      arguments: [
        vscode.Uri.file(finding.meta.fileUri),
        {
          selection: new vscode.Range(
            finding.candidate.lineNumber,
            finding.candidate.startChar,
            finding.candidate.lineNumber,
            finding.candidate.endChar,
          ),
        },
      ],
    };
    treeItem.contextValue = "finding";
    treeItem.iconPath = new vscode.ThemeIcon(
      "warning",
      new vscode.ThemeColor(SEVERITY_THEME_COLORS[finding.severity]),
    );

    return treeItem;
  }

  private buildEmptyItem(): vscode.TreeItem {
    const item = new vscode.TreeItem("No secrets detected");
    item.description = "Your code is clean";
    item.iconPath = new vscode.ThemeIcon(
      "shield",
      new vscode.ThemeColor("charts.green"),
    );
    return item;
  }
}
