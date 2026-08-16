/**
 * VS Code API mock for Jest testing.
 * Provides stubs for all VS Code APIs used by the extension.
 */

export enum DiagnosticSeverity {
  Error = 0,
  Warning = 1,
  Information = 2,
  Hint = 3,
}

export class Range {
  constructor(
    public readonly start: Position,
    public readonly end: Position,
  ) {}
}

export class Position {
  constructor(
    public readonly line: number,
    public readonly character: number,
  ) {}
}

export class Diagnostic {
  public source?: string;
  public code?: string | number;
  public relatedInformation?: DiagnosticRelatedInformation[];
  public tags?: DiagnosticTag[];

  constructor(
    public range: Range,
    public message: string,
    public severity: DiagnosticSeverity = DiagnosticSeverity.Warning,
  ) {}
}

export interface DiagnosticRelatedInformation {
  location: { uri: Uri; range: Range };
  message: string;
}

export enum DiagnosticTag {
  Unnecessary = 1,
  Deprecated = 2,
}

export class Uri {
  public readonly scheme: string = "file";
  public readonly path: string;
  public readonly fsPath: string;

  private constructor(fsPath: string) {
    this.path = fsPath;
    this.fsPath = fsPath;
  }

  public static file(path: string): Uri {
    const uri = new Uri(path);
    return uri;
  }

  public toString(): string {
    return `file://${this.fsPath}`;
  }
}

export class CodeAction {
  public command?: Command;
  public edit?: WorkspaceEdit;
  public diagnostics?: Diagnostic[];
  public isPreferred?: boolean;

  constructor(
    public title: string,
    public kind?: CodeActionKind,
  ) {}
}

export class CodeActionKind {
  public static readonly Empty = new CodeActionKind("");
  public static readonly QuickFix = new CodeActionKind("quickfix");
  public static readonly Refactor = new CodeActionKind("refactor");
  public static readonly Source = new CodeActionKind("source");

  private constructor(public readonly value: string) {}

  public append(parts: string): CodeActionKind {
    return new CodeActionKind(`${this.value}.${parts}`);
  }
}

export interface Command {
  title: string;
  command: string;
  arguments?: unknown[];
}

export class WorkspaceEdit {
  private edits: Map<string, Array<{ range: Range; newText: string }>> =
    new Map();

  public replace(uri: Uri, range: Range, newText: string): void {
    const key = uri.fsPath;
    const existing = this.edits.get(key) ?? [];
    existing.push({ range, newText });
    this.edits.set(key, existing);
  }

  public getEdits(uri: Uri): Array<{ range: Range; newText: string }> {
    return this.edits.get(uri.fsPath) ?? [];
  }
}

export const window = {
  showInformationMessage: jest.fn().mockResolvedValue(undefined),
  showWarningMessage: jest.fn().mockResolvedValue(undefined),
  showErrorMessage: jest.fn().mockResolvedValue(undefined),
  createOutputChannel: jest.fn().mockReturnValue({
    appendLine: jest.fn(),
    append: jest.fn(),
    show: jest.fn(),
    hide: jest.fn(),
    dispose: jest.fn(),
    clear: jest.fn(),
  }),
  createStatusBarItem: jest.fn().mockReturnValue({
    text: "",
    tooltip: "",
    command: "",
    show: jest.fn(),
    hide: jest.fn(),
    dispose: jest.fn(),
  }),
  createTreeView: jest.fn().mockReturnValue({
    reveal: jest.fn(),
    dispose: jest.fn(),
    onDidExpandElement: { event: jest.fn() },
    onDidCollapseElement: { event: jest.fn() },
    onDidChangeSelection: { event: jest.fn() },
    onDidChangeVisibility: { event: jest.fn() },
  }),
  createWebviewPanel: jest.fn().mockReturnValue({
    webview: {
      html: "",
      postMessage: jest.fn(),
      onDidReceiveMessage: jest.fn(),
      asWebviewUri: jest.fn((uri: Uri) => uri),
      cspSource: "vscode-resource:",
    },
    onDidDispose: jest.fn(),
    reveal: jest.fn(),
    dispose: jest.fn(),
    visible: true,
    active: true,
  }),
  activeTextEditor: undefined as unknown,
  visibleTextEditors: [] as unknown[],
  onDidChangeActiveTextEditor: jest.fn(),
  onDidChangeTextEditorSelection: jest.fn(),
};

export const workspace = {
  getConfiguration: jest.fn().mockReturnValue({
    get: jest.fn().mockReturnValue(undefined),
    update: jest.fn().mockResolvedValue(undefined),
    has: jest.fn().mockReturnValue(false),
  }),
  workspaceFolders: undefined as unknown,
  onDidChangeTextDocument: jest.fn(),
  onDidOpenTextDocument: jest.fn(),
  onDidSaveTextDocument: jest.fn(),
  onDidCloseTextDocument: jest.fn(),
  createFileSystemWatcher: jest.fn().mockReturnValue({
    onDidChange: jest.fn(),
    onDidCreate: jest.fn(),
    onDidDelete: jest.fn(),
    dispose: jest.fn(),
  }),
  findFiles: jest.fn().mockResolvedValue([]),
  openTextDocument: jest.fn(),
  applyEdit: jest.fn().mockResolvedValue(true),
  fs: {
    readFile: jest.fn(),
    writeFile: jest.fn(),
    stat: jest.fn(),
    createDirectory: jest.fn(),
    delete: jest.fn(),
  },
};

export const commands = {
  registerCommand: jest.fn().mockReturnValue({ dispose: jest.fn() }),
  executeCommand: jest.fn().mockResolvedValue(undefined),
};

export const languages = {
  createDiagnosticCollection: jest.fn().mockReturnValue({
    set: jest.fn(),
    delete: jest.fn(),
    clear: jest.fn(),
    dispose: jest.fn(),
    get: jest.fn().mockReturnValue([]),
    forEach: jest.fn(),
  }),
  registerCodeActionsProvider: jest
    .fn()
    .mockReturnValue({ dispose: jest.fn() }),
  registerHoverProvider: jest.fn().mockReturnValue({ dispose: jest.fn() }),
};

export const ExtensionContext = {
  subscriptions: [] as Array<{ dispose: () => void }>,
  globalState: {
    get: jest.fn().mockReturnValue(undefined),
    update: jest.fn().mockResolvedValue(undefined),
    keys: jest.fn().mockReturnValue([]),
  },
  workspaceState: {
    get: jest.fn().mockReturnValue(undefined),
    update: jest.fn().mockResolvedValue(undefined),
    keys: jest.fn().mockReturnValue([]),
  },
  extensionPath: "/mock/extension/path",
  extensionUri: Uri.file("/mock/extension/path"),
  storagePath: "/mock/storage",
  globalStoragePath: "/mock/global-storage",
  logPath: "/mock/log",
  asAbsolutePath: jest.fn(
    (relativePath: string) => `/mock/extension/path/${relativePath}`,
  ),
};

export enum StatusBarAlignment {
  Left = 1,
  Right = 2,
}

export enum TreeItemCollapsibleState {
  None = 0,
  Collapsed = 1,
  Expanded = 2,
}

export class TreeItem {
  public iconPath?: string | Uri | { light: Uri; dark: Uri };
  public description?: string;
  public tooltip?: string;
  public command?: Command;
  public contextValue?: string;

  constructor(
    public label: string,
    public collapsibleState?: TreeItemCollapsibleState,
  ) {}
}

export class ThemeIcon {
  constructor(
    public id: string,
    public color?: ThemeColor,
  ) {}
}

export class ThemeColor {
  constructor(public id: string) {}
}

export enum ViewColumn {
  Active = -1,
  Beside = -2,
  One = 1,
  Two = 2,
  Three = 3,
}

export const env = {
  clipboard: {
    readText: jest.fn().mockResolvedValue(""),
    writeText: jest.fn().mockResolvedValue(undefined),
  },
  openExternal: jest.fn().mockResolvedValue(true),
  uriScheme: "vscode",
};

export class EventEmitter<T> {
  public event = jest.fn();
  public fire(_data: T): void {}
  public dispose(): void {}
}

export const FileDecoration = class {
  constructor(
    public badge?: string,
    public tooltip?: string,
    public color?: ThemeColor,
  ) {}
};

export default {
  DiagnosticSeverity,
  Range,
  Position,
  Diagnostic,
  Uri,
  CodeAction,
  CodeActionKind,
  WorkspaceEdit,
  window,
  workspace,
  commands,
  languages,
  ExtensionContext,
  StatusBarAlignment,
  TreeItemCollapsibleState,
  TreeItem,
  ThemeIcon,
  ThemeColor,
  ViewColumn,
  env,
  EventEmitter,
  FileDecoration,
};
