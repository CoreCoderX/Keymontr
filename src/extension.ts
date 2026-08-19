import * as vscode from "vscode";
import { DatabaseManager } from "./database/DatabaseManager.js";
import { DashboardPanel } from "./vscode/views/DashboardPanel.js";
import { ConfigurationManager } from "./config/ConfigurationManager.js";
import { Pipeline } from "./core/pipeline/Pipeline.js";
import { Gate8_DeveloperMemory } from "./core/pipeline/Gate8_DeveloperMemory.js";
import {
  GlobalStateManager,
  STORAGE_KEYS,
} from "./storage/GlobalStateManager.js";
import { DeveloperMemoryStore } from "./storage/DeveloperMemoryStore.js";
import { SecretHistoryStore } from "./storage/SecretHistoryStore.js";
import { DiagnosticProvider } from "./vscode/providers/DiagnosticProvider.js";
import { KeymontrCodeActionProvider } from "./vscode/providers/CodeActionProvider.js";
import { KeymontrHoverProvider } from "./vscode/providers/HoverProvider.js";
import { KeymontrDecorationProvider } from "./vscode/providers/DecorationProvider.js";
import { KeymontrTreeDataProvider } from "./vscode/providers/TreeDataProvider.js";
import { StatusBarManager } from "./vscode/views/StatusBarManager.js";
import { RemediationOrchestrator } from "./remediation/RemediationOrchestrator.js";
import { GitHookManager } from "./git/GitHookManager.js";
import { GitIgnoreService } from "./git/GitIgnoreMatcher.js";
import { CommandRegistry } from "./vscode/commands/CommandRegistry.js";
import { AIAssistantDetector } from "./ai/AIAssistantDetector.js";
import { SeverityLevel, SEVERITY_NUMERIC } from "./core/types/SeverityLevel.js";
import { PipelineResult, SecretFinding } from "./core/types/SecretFinding.js";

// Debounce timer for real-time typing detection
let typingDebounceTimer: ReturnType<typeof setTimeout> | undefined;

// All disposables collected for cleanup
const disposables: vscode.Disposable[] = [];

// Pipeline result cache: fileUri → PipelineResult
const resultCache = new Map<string, PipelineResult>();

// Git-ignore evaluation (workspace-aware)
let gitIgnoreService: GitIgnoreService;


/**
 * Extension activation — called once when VS Code loads Keymontr.
 */
export async function activate(
  context: vscode.ExtensionContext,
): Promise<void> {
  const outputChannel = vscode.window.createOutputChannel(
    "Keymontr",
    "log",
  );
  outputChannel.appendLine("[Keymontr] Activating...");
  context.subscriptions.push(outputChannel);

  // ── Workspace root ─────────────────────────────────────────────────────────
  const workspaceRoot =
    vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? context.extensionPath;

  // ── Git-ignore resolution ─────────────────────────────────────────────────
  gitIgnoreService = new GitIgnoreService(workspaceRoot);

  // ── Configuration ──────────────────────────────────────────────────────────
  const configManager = new ConfigurationManager();
  configManager.load(workspaceRoot);

  const warnings = configManager.getValidationWarnings();
  for (const warning of warnings) {
    outputChannel.appendLine(`[Keymontr] Config warning: ${warning}`);
  }

  // ── Database initialization ────────────────────────────────────────────────
  const dbManager = DatabaseManager.getInstance();

  try {
    await dbManager.initialize(context.extensionPath);
    const health = dbManager.getHealthReport();
    outputChannel.appendLine(
      `[Keymontr] DB1 loaded: ${health.db1.ruleCount} rules`,
    );
    outputChannel.appendLine(
      `[Keymontr] DB2 loaded: ${health.db2.keywordCount} keywords`,
    );
  } catch (err) {
    outputChannel.appendLine(
      `[Keymontr] CRITICAL: Database initialization failed: ${String(err)}`,
    );
    await vscode.window.showErrorMessage(
      `Keymontr: Database initialization failed. Extension may not work correctly. ${String(err)}`,
    );
    return;
  }

  // ── Core engine ────────────────────────────────────────────────────────────
  const gate8 = new Gate8_DeveloperMemory();
  const pipeline = new Pipeline(dbManager, configManager, gate8);

  // ── Storage ────────────────────────────────────────────────────────────────
  const globalState = new GlobalStateManager(context);
  const memoryStore = new DeveloperMemoryStore(gate8, globalState);
  const historyStore = new SecretHistoryStore(globalState);

  memoryStore.loadFromStorage();
  historyStore.load();

  // ── VS Code providers ──────────────────────────────────────────────────────
  const diagnosticProvider = new DiagnosticProvider();
  const codeActionProvider = new KeymontrCodeActionProvider();
  const hoverProvider = new KeymontrHoverProvider();
  const decorationProvider = new KeymontrDecorationProvider();
  const treeProvider = new KeymontrTreeDataProvider();
  const statusBar = new StatusBarManager();

  context.subscriptions.push(diagnosticProvider);
  context.subscriptions.push(decorationProvider);
  context.subscriptions.push(statusBar);

  // Register providers with VS Code
  const DOCUMENT_SELECTOR: vscode.DocumentSelector = [
    { scheme: "file", language: "typescript" },
    { scheme: "file", language: "typescriptreact" },
    { scheme: "file", language: "javascript" },
    { scheme: "file", language: "javascriptreact" },
    { scheme: "file", language: "python" },
    { scheme: "file", language: "go" },
    { scheme: "file", language: "rust" },
    { scheme: "file", language: "java" },
    { scheme: "file", language: "csharp" },
    { scheme: "file", language: "php" },
    { scheme: "file", language: "ruby" },
    { scheme: "file", language: "yaml" },
    { scheme: "file", language: "json" },
    { scheme: "file", language: "toml" },
    { scheme: "file", language: "shellscript" },
    { scheme: "file", language: "dotenv" },
    { scheme: "file" },
  ];

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      DOCUMENT_SELECTOR,
      codeActionProvider,
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
    ),
  );

  context.subscriptions.push(
    vscode.languages.registerHoverProvider(DOCUMENT_SELECTOR, hoverProvider),
  );

  context.subscriptions.push(
    vscode.window.registerFileDecorationProvider(decorationProvider),
  );

  context.subscriptions.push(
    vscode.window.createTreeView("keymontr.findingsView", {
      treeDataProvider: treeProvider,
      showCollapseAll: true,
    }),
  );

  // ── Remediation & Git ──────────────────────────────────────────────────────
  const cfg = configManager.getConfig();

  const orchestrator = new RemediationOrchestrator(
    workspaceRoot,
    historyStore,
    cfg.remediation.preferredEnvFileName,
  );

  const gitHookManager = new GitHookManager(workspaceRoot);

  // ── Commands ───────────────────────────────────────────────────────────────
  const commandRegistry = new CommandRegistry(
    context,
    orchestrator,
    memoryStore,
    historyStore,
    gitHookManager,
    treeProvider,
    diagnosticProvider,
    decorationProvider,
    gate8,
    cfg,
    workspaceRoot,
    dbManager,
  );
  commandRegistry.registerAll();

  // Internal full-scan command (used by workspace scan)
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "keymontr.internalFullScan",
      async () => {
        await performFullWorkspaceScan(
          pipeline,
          diagnosticProvider,
          codeActionProvider,
          hoverProvider,
          decorationProvider,
          treeProvider,
          statusBar,
          historyStore,
          outputChannel,
        );
      },
    ),
  );

  // ── File event listeners ───────────────────────────────────────────────────

  // On file open — scan the opened file
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(async (doc) => {
      if (doc.uri.scheme !== "file") {
        return;
      }
      await scanFile(
        doc.uri.fsPath,
        doc.getText(),
        doc.languageId,
        "open",
        undefined,
        pipeline,
        diagnosticProvider,
        codeActionProvider,
        hoverProvider,
        decorationProvider,
        treeProvider,
        statusBar,
        historyStore,
        outputChannel,
      );
    }),
  );

  // On file save — always re-scan the full file
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.uri.scheme !== "file") {
        return;
      }
      await scanFile(
        doc.uri.fsPath,
        doc.getText(),
        doc.languageId,
        "save",
        undefined,
        pipeline,
        diagnosticProvider,
        codeActionProvider,
        hoverProvider,
        decorationProvider,
        treeProvider,
        statusBar,
        historyStore,
        outputChannel,
      );
    }),
  );

  // On typing — debounced, incremental
  if (cfg.detection !== undefined) {
    context.subscriptions.push(
      vscode.workspace.onDidChangeTextDocument((event) => {
        if (event.document.uri.scheme !== "file") {
          return;
        }
        if (event.contentChanges.length === 0) {
          return;
        }

        const changedLines = [
          ...new Set(event.contentChanges.map((c) => c.range.start.line)),
        ];

        if (typingDebounceTimer !== undefined) {
          clearTimeout(typingDebounceTimer);
        }

        typingDebounceTimer = setTimeout(() => {
          const doc = event.document;
          void scanFile(
            doc.uri.fsPath,
            doc.getText(),
            doc.languageId,
            "typing",
            changedLines,
            pipeline,
            diagnosticProvider,
            codeActionProvider,
            hoverProvider,
            decorationProvider,
            treeProvider,
            statusBar,
            historyStore,
            outputChannel,
          );
        }, cfg.detection.debounceMs);
      }),
    );
  }

  // ── AI Assistant Notice ────────────────────────────────────────────────────
  const aiDetector = new AIAssistantDetector(context);
  setTimeout(() => {
    void aiDetector.showNoticeIfNeeded();
  }, 3000); // Delay to not interrupt activation

  // ── First activation message ───────────────────────────────────────────────
  const isFirstActivation = !globalState.has(STORAGE_KEYS.FIRST_ACTIVATION);
  if (isFirstActivation) {
    await globalState.set(STORAGE_KEYS.FIRST_ACTIVATION, true);

    // Offer to install Git hook
    if (gitHookManager.isGitRepository() && !gitHookManager.isHookInstalled()) {
      const choice = await vscode.window.showInformationMessage(
        "Keymontr is active! Install Git pre-commit hook to block secret commits?",
        "Install Hook",
        "Not Now",
        "Never",
      );

      if (choice === "Install Hook") {
        await vscode.commands.executeCommand("keymontr.installGitHook");
      } else if (choice === "Never") {
        await globalState.set("keymontr.neverInstallHook", true);
      }
    }
  }

  // ── Scan open editors on startup ───────────────────────────────────────────
  for (const editor of vscode.window.visibleTextEditors) {
    if (editor.document.uri.scheme === "file") {
      void scanFile(
        editor.document.uri.fsPath,
        editor.document.getText(),
        editor.document.languageId,
        "open",
        undefined,
        pipeline,
        diagnosticProvider,
        codeActionProvider,
        hoverProvider,
        decorationProvider,
        treeProvider,
        statusBar,
        historyStore,
        outputChannel,
      );
    }
  }

  outputChannel.appendLine("[Keymontr] Activated successfully.");
}

/**
 * Scans a single file through the pipeline and updates all providers.
 */
async function scanFile(
  fileUri: string,
  content: string,
  languageId: string,
  triggerType: "typing" | "save" | "open" | "manual-scan" | "pre-commit",
  changedLines: number[] | undefined,
  pipeline: Pipeline,
  diagnosticProvider: DiagnosticProvider,
  codeActionProvider: KeymontrCodeActionProvider,
  hoverProvider: KeymontrHoverProvider,
  decorationProvider: KeymontrDecorationProvider,
  treeProvider: KeymontrTreeDataProvider,
  statusBar: StatusBarManager,
  historyStore: SecretHistoryStore,
  outputChannel: vscode.OutputChannel,
): Promise<void> {
  try {
    // Git-ignored files (e.g. .env once it is listed in .gitignore) cannot
    // be committed, so there is no leak risk. Clear any stale markers and
    // skip scanning them entirely.
    if (gitIgnoreService.isFileIgnored(fileUri)) {
      diagnosticProvider.clearFile(vscode.Uri.file(fileUri));
      decorationProvider.setFileRisk(fileUri, null);
      treeProvider.updateFindings(fileUri, []);
      return;
    }

    statusBar.showScanning();

    const result = pipeline.run({
      fileUri,
      fileContent: content,
      languageId,
      triggerType,
      ...(changedLines !== undefined ? { changedLines } : {}),
    });

    const vsUri = vscode.Uri.file(fileUri);

    // Update diagnostic provider
    diagnosticProvider.update(vsUri, result);

    // Register findings with code action and hover providers
    codeActionProvider.clearFindingsForFile(fileUri);
    hoverProvider.clearFindingsForFile(fileUri);

    for (const finding of result.findings) {
      codeActionProvider.registerFinding(finding);
      hoverProvider.registerFinding(finding);
    }

    // Update tree view
    treeProvider.updateFindings(fileUri, result.findings);

    // Update the open dashboard panel (no-op when closed)
    DashboardPanel.updateFindingsIfOpen(result.findings);

    // Update file decoration
    const highestSeverity = getHighestSeverity(result.findings);
    decorationProvider.setFileRisk(fileUri, highestSeverity);

    // Update status bar
    const totalFindings = treeProvider.totalCount;
    if (totalFindings === 0) {
      statusBar.showClean();
    } else if (highestSeverity !== null) {
      statusBar.showFindings(totalFindings, highestSeverity);
    }

    // Record new findings in history
    for (const finding of result.findings) {
      await historyStore.recordDetection(finding);
    }

    // Cache result for this file
    resultCache.set(fileUri, result);

    if (result.findings.length > 0) {
      outputChannel.appendLine(
        `[Keymontr] ${fileUri}: ${result.findings.length} finding(s) ` +
          `in ${result.stats.processingTimeMs}ms`,
      );
    }
  } catch (err) {
    statusBar.showError(String(err));
    outputChannel.appendLine(
      `[Keymontr] Error scanning ${fileUri}: ${String(err)}`,
    );
  }
}

/**
 * Performs a full workspace scan across all relevant files.
 */
async function performFullWorkspaceScan(
  pipeline: Pipeline,
  diagnosticProvider: DiagnosticProvider,
  codeActionProvider: KeymontrCodeActionProvider,
  hoverProvider: KeymontrHoverProvider,
  decorationProvider: KeymontrDecorationProvider,
  treeProvider: KeymontrTreeDataProvider,
  statusBar: StatusBarManager,
  historyStore: SecretHistoryStore,
  outputChannel: vscode.OutputChannel,
): Promise<void> {
  statusBar.showScanning();

  const files = await vscode.workspace.findFiles(
    "**/*",
    "{**/node_modules/**,**/dist/**,**/build/**,**/.git/**,**/coverage/**}",
  );

  outputChannel.appendLine(
    `[Keymontr] Full scan: ${files.length} files found`,
  );

  diagnosticProvider.clearAll();
  decorationProvider.clearAll();
  treeProvider.clearAll();

  let scanned = 0;
  let totalFindings = 0;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "Keymontr: Scanning workspace...",
      cancellable: true,
    },
    async (progress, token) => {
      for (const fileUri of files) {
        if (token.isCancellationRequested) {
          break;
        }

        try {
          const bytes = await vscode.workspace.fs.readFile(fileUri);
          const content = Buffer.from(bytes).toString("utf-8");

          const ext = fileUri.fsPath.split(".").pop() ?? "";
          const langId = ext;

          await scanFile(
            fileUri.fsPath,
            content,
            langId,
            "manual-scan",
            undefined,
            pipeline,
            diagnosticProvider,
            codeActionProvider,
            hoverProvider,
            decorationProvider,
            treeProvider,
            statusBar,
            historyStore,
            outputChannel,
          );

          scanned++;
          totalFindings = treeProvider.totalCount;

          progress.report({
            message: `${scanned}/${files.length} — ${totalFindings} findings`,
            increment: (1 / files.length) * 100,
          });
        } catch {
          // Skip unreadable files
        }
      }
    },
  );

  if (totalFindings === 0) {
    statusBar.showClean();
    await vscode.window.showInformationMessage(
      `Keymontr: Workspace scan complete. ${scanned} files scanned. No secrets found.`,
    );
  } else {
    await vscode.window.showWarningMessage(
      `Keymontr: Found ${totalFindings} potential secret(s) in ${scanned} files. Check the sidebar.`,
    );
  }

  outputChannel.appendLine(
    `[Keymontr] Full scan complete: ${scanned} files, ${totalFindings} findings`,
  );
}

/**
 * Returns the highest severity level from a list of findings.
 */
function getHighestSeverity(findings: SecretFinding[]): SeverityLevel | null {
  if (findings.length === 0) {
    return null;
  }

  return findings.reduce<SeverityLevel | null>((highest, finding) => {
    if (highest === null) {
      return finding.severity;
    }
    return SEVERITY_NUMERIC[finding.severity] > SEVERITY_NUMERIC[highest]
      ? finding.severity
      : highest;
  }, null);
}

/**
 * Extension deactivation — called when VS Code unloads Keymontr.
 */
export function deactivate(): void {
  if (typingDebounceTimer !== undefined) {
    clearTimeout(typingDebounceTimer);
  }
  for (const disposable of disposables) {
    disposable.dispose();
  }
  DatabaseManager.reset();
}
