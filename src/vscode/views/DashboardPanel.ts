import * as vscode from "vscode";
import * as path from "path";
import * as crypto from "crypto";
import * as fs from "fs";
import { SecretHistoryStore } from "../../storage/SecretHistoryStore.js";
import { DeveloperMemoryStore } from "../../storage/DeveloperMemoryStore.js";
import { GitHookManager } from "../../git/GitHookManager.js";
import { DatabaseManager } from "../../database/DatabaseManager.js";
import { SecretFinding } from "../../core/types/SecretFinding.js";
import { AIAssistantDetector } from "../../ai/AIAssistantDetector.js";

/**
 * DashboardPanel — Manages the Keymontr webview dashboard.
 *
 * Uses VS Code's WebviewPanel API to render the HTML dashboard.
 * Communicates bidirectionally with the dashboard JS via postMessage.
 * Enforces strict Content Security Policy for XSS prevention.
 */
export class DashboardPanel {
  private static currentPanel: DashboardPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  private constructor(
    panel: vscode.WebviewPanel,
    private readonly extensionUri: vscode.Uri,
    private readonly historyStore: SecretHistoryStore,
    private readonly memoryStore: DeveloperMemoryStore,
    private readonly gitHookManager: GitHookManager,
    private readonly dbManager: DatabaseManager,
    private readonly aiDetector: AIAssistantDetector,
    private activeFindings: SecretFinding[] = [],
  ) {
    this.panel = panel;
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
    this.panel.webview.onDidReceiveMessage(
      (msg: { command: string; payload?: unknown }) => this.handleMessage(msg),
      null,
      this.disposables,
    );

    this.render();
    this.pushData();
  }

  /**
   * Creates or reveals the dashboard panel.
   */
  public static createOrShow(
    extensionUri: vscode.Uri,
    historyStore: SecretHistoryStore,
    memoryStore: DeveloperMemoryStore,
    gitHookManager: GitHookManager,
    dbManager: DatabaseManager,
    aiDetector: AIAssistantDetector,
    activeFindings: SecretFinding[] = [],
  ): DashboardPanel {
    const column =
      vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

    if (DashboardPanel.currentPanel !== undefined) {
      DashboardPanel.currentPanel.panel.reveal(column);
      DashboardPanel.currentPanel.activeFindings = activeFindings;
      DashboardPanel.currentPanel.pushData();
      return DashboardPanel.currentPanel;
    }

    const panel = vscode.window.createWebviewPanel(
      "keymontrDashboard",
      "Keymontr Dashboard",
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.joinPath(extensionUri, "dist", "dashboard"),
          vscode.Uri.joinPath(
            extensionUri,
            "src",
            "vscode",
            "views",
            "dashboard",
          ),
        ],
      },
    );

    DashboardPanel.currentPanel = new DashboardPanel(
      panel,
      extensionUri,
      historyStore,
      memoryStore,
      gitHookManager,
      dbManager,
      aiDetector,
      activeFindings,
    );

    return DashboardPanel.currentPanel;
  }

  /**
   * Pushes the full dataset to the open dashboard panel (no-op if closed).
   * Called whenever findings change so the UI stays live without reopening.
   */
  public static refreshIfOpen(findings?: SecretFinding[]): void {
    if (DashboardPanel.currentPanel !== undefined) {
      DashboardPanel.currentPanel.refresh(findings);
    }
  }

  /**
   * Refreshes the panel with the latest findings and pushes all data.
   */
  public refresh(findings?: SecretFinding[]): void {
    if (findings !== undefined) {
      this.activeFindings = findings;
    }
    this.pushData();
  }

  /**
   * Renders the dashboard HTML into the webview.
   */
  private render(): void {
    const nonce = this.generateNonce();
    const webview = this.panel.webview;

    const cssUri = webview.asWebviewUri(
      vscode.Uri.joinPath(
        this.extensionUri,
        "src",
        "vscode",
        "views",
        "dashboard",
        "dashboard.css",
      ),
    );

    const jsUri = webview.asWebviewUri(
      vscode.Uri.joinPath(
        this.extensionUri,
        "src",
        "vscode",
        "views",
        "dashboard",
        "dashboard.js",
      ),
    );

    const htmlPath = path.join(
      this.extensionUri.fsPath,
      "src",
      "vscode",
      "views",
      "dashboard",
      "index.html",
    );

    let html = fs.readFileSync(htmlPath, "utf-8");

    // Replace template variables
    html = html
      .replace(/\{\{NONCE\}\}/g, nonce)
      .replace(/\{\{CSP_SOURCE\}\}/g, webview.cspSource)
      .replace(/\{\{DASHBOARD_CSS_URI\}\}/g, cssUri.toString())
      .replace(/\{\{DASHBOARD_JS_URI\}\}/g, jsUri.toString());

    webview.html = html;
  }

  /**
   * Pushes all data to the dashboard.
   */
  private pushData(): void {
    const stats = this.historyStore.getStatistics();
    const history = this.historyStore.getHistory();
    const dbHealth = this.dbManager.getHealthReport();
    const gitHookInstalled = this.gitHookManager.isHookInstalled();

    // Ignored keys = permanent suppressions (marked as safe) plus session-only
    // ignores (live until restart). Raw line content is deliberately NOT sent
    // — never ship secret values to the UI.
    const ignoredKeys = this.memoryStore
      .getAllIgnored()
      .sort(
        (a, b) =>
          new Date(b.suppressedAt).getTime() -
          new Date(a.suppressedAt).getTime(),
      )
      .map((s) => ({
        fileUri: s.fileUri,
        fileName: path.basename(s.fileUri),
        lineNumber: s.lineNumber ?? 0,
        severity: s.severity,
        ruleName: s.ruleId ?? undefined,
        reason: s.reason ?? undefined,
        ignoredAt: s.suppressedAt,
        kind: s.kind,
      }));

    const aiAgents = this.aiDetector.getInstalledAssistants();

    this.postMessage("updateData", {
      findings: this.activeFindings,
      history: history.slice(0, 100),
      stats,
      dbHealth,
      gitHookInstalled,
      ignoredKeys,
      aiAgents,
    });
  }

  /**
   * Handles messages received from the dashboard webview.
   */
  private handleMessage(message: { command: string; payload?: unknown }): void {
    switch (message.command) {
      case "requestData":
        this.pushData();
        break;

      case "scanWorkspace":
        void vscode.commands.executeCommand("keymontr.scanWorkspace");
        break;

      case "exportReport":
        void vscode.commands.executeCommand("keymontr.exportReport");
        break;

      case "clearHistory":
        void vscode.commands.executeCommand("keymontr.clearHistory");
        setTimeout(() => this.pushData(), 500);
        break;

      case "installGitHook":
        void vscode.commands
          .executeCommand("keymontr.installGitHook")
          .then(() => {
            this.postMessage(
              "updateGitHook",
              this.gitHookManager.isHookInstalled(),
            );
          });
        break;

      case "removeGitHook":
        void vscode.commands
          .executeCommand("keymontr.removeGitHook")
          .then(() => {
            this.postMessage(
              "updateGitHook",
              this.gitHookManager.isHookInstalled(),
            );
          });
        break;

      default:
        break;
    }
  }

  private postMessage(type: string, payload: unknown): void {
    void this.panel.webview.postMessage({ type, payload });
  }

  private generateNonce(): string {
    return crypto.randomBytes(16).toString("base64");
  }

  public dispose(): void {
    DashboardPanel.currentPanel = undefined;
    this.panel.dispose();
    for (const d of this.disposables) {
      d.dispose();
    }
    this.disposables = [];
  }
}
