import * as vscode from "vscode";
import * as path from "path";
import { SecretFinding, SuppressionRecord } from "../../core/types/SecretFinding.js";
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
  ignored?: SuppressionRecord & { kind: "permanent" | "session" };
  children?: FindingsTreeItem[];
}

/**
 * TreeDataProvider — Populates the Keymontr sidebar tree view.
 *
 * Structure:
 * ├── Critical (2)          ◉ (errorForeground icon)
 * │   ├── config.ts:12 — OpenAI API Key
 * │   └── .env:4 — AWS Access Token
 * ├── High (1)              ◉ (charts.orange icon)
 * │   └── database.js:8 — Generic API Key
 * └── No Issues             ◉ (shield icon)
 */
export class KeymontrTreeDataProvider implements vscode.TreeDataProvider<FindingsTreeItem> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<
    FindingsTreeItem | undefined | null | void
  >();

  public readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  // All current findings across all files
  private allFindings: Map<string, SecretFinding[]> = new Map();

  // Ignored (suppressed) entries shown in the "Ignored" group
  private ignoredItems: Array<
    SuppressionRecord & { kind: "permanent" | "session" }
  > = [];

  /**
   * Updates the ignored/suppressed entries shown in the tree.
   */
  public updateIgnored(
    items: Array<SuppressionRecord & { kind: "permanent" | "session" }>,
  ): void {
    this.ignoredItems = items;
    this._onDidChangeTreeData.fire();
  }

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
   * Removes a single finding (e.g. after it was marked safe / ignored)
   * and refreshes the tree.
   */
  public removeFinding(findingId: string): void {
    for (const [fileUri, findings] of this.allFindings) {
      const remaining = findings.filter((f) => f.id !== findingId);
      if (remaining.length !== findings.length) {
        if (remaining.length === 0) {
          this.allFindings.delete(fileUri);
        } else {
          this.allFindings.set(fileUri, remaining);
        }
        this._onDidChangeTreeData.fire();
        return;
      }
    }
  }

  /**
   * Returns all current findings across all scanned files.
   */
  public getAllFindings(): SecretFinding[] {
    return Array.from(this.allFindings.values()).flat();
  }

  /**
   * Returns the findings currently tracked for a specific file.
   */
  public getFindingsForFile(fileUri: string): SecretFinding[] {
    return this.allFindings.get(fileUri) ?? [];
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

    // Ignored group — permanently suppressed + session-only suppressions
    if (this.ignoredItems.length > 0) {
      const ignoredChildren: FindingsTreeItem[] = this.ignoredItems.map((s) => ({
        type: "finding",
        label: `${path.basename(s.fileUri)}:${(s.lineNumber ?? 0) + 1}`,
        ignored: s,
      }));
      items.push({
        type: "severity-group",
        label: `Ignored (${this.ignoredItems.length})`,
        children: ignoredChildren,
      });
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

    if (item.label.startsWith("Ignored")) {
      treeItem.contextValue = "ignored-group";
      treeItem.iconPath = new vscode.ThemeIcon(
        "check",
        new vscode.ThemeColor("charts.green"),
      );
      return treeItem;
    }

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
    const ignored = item.ignored;
    if (ignored !== undefined) {
      const treeItem = new vscode.TreeItem(
        item.label,
        vscode.TreeItemCollapsibleState.None,
      );
      const kind = ignored.kind === "session" ? "Ignored for session" : "Suppressed";
      const rule = ignored.ruleId ?? "unknown rule";
      const reason = ignored.reason ?? "no reason given";

      treeItem.description = kind;
      treeItem.tooltip = new vscode.MarkdownString(
        `**${kind}**\n\nRule: \`${rule}\`\n\nReason: ${reason}`,
      );
      treeItem.command = {
        title: "Go to suppressed line",
        command: "vscode.open",
        arguments: [
          vscode.Uri.file(ignored.fileUri),
          {
            selection: new vscode.Range(
              ignored.lineNumber ?? 0,
              0,
              ignored.lineNumber ?? 0,
              0,
            ),
          },
        ],
      };
      treeItem.contextValue = "ignored";
      treeItem.iconPath = new vscode.ThemeIcon(
        "mute",
        new vscode.ThemeColor("charts.green"),
      );
      return treeItem;
    }

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
