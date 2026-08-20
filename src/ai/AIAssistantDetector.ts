import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/**
 * AIAssistantDetector — Detects known AI coding assistant extensions.
 *
 * This is purely INFORMATIONAL. It does NOT block or interfere with
 * any AI assistant. It reports which assistants are installed / active
 * and shows a one-time notice reminding developers to be mindful about
 * sharing sensitive files or credentials with AI assistants.
 *
 * The agent registry lives in <extensionRoot>/agents/ai-agents.json so the
 * list can be extended without a code change. If the file is missing or
 * malformed, a built-in fallback list is used so detection never breaks.
 */

/** A known AI coding assistant entry from the registry. */
export interface AIAgent {
  id: string;
  name: string;
  vendor?: string;
  category?: string;
  url?: string;
}

/** An agent resolved against the local VS Code instance. */
export interface DetectedAIAgent extends AIAgent {
  /** Whether the extension is installed (and enabled) in this VS Code. */
  installed: boolean;
  /** Whether the extension has been activated in this session. */
  active: boolean;
}

/**
 * Fallback registry used when agents/ai-agents.json cannot be loaded.
 * Kept deliberately small — the authoritative list lives in the JSON file.
 */
const FALLBACK_AGENTS: AIAgent[] = [
  { id: "GitHub.copilot", name: "GitHub Copilot", vendor: "GitHub" },
  { id: "GitHub.copilot-chat", name: "GitHub Copilot Chat", vendor: "GitHub" },
  { id: "Anthropic.claude-code", name: "Claude Code", vendor: "Anthropic" },
  { id: "Google.geminicodeassist", name: "Gemini Code Assist", vendor: "Google" },
  {
    id: "AmazonWebServices.amazon-q-vscode",
    name: "Amazon Q Developer",
    vendor: "AWS",
  },
  { id: "Continue.continue", name: "Continue", vendor: "Continue Dev" },
  { id: "Codeium.codeium", name: "Windsurf Plugin (Codeium)", vendor: "Windsurf" },
  { id: "TabNine.tabnine-vscode", name: "Tabnine", vendor: "Tabnine" },
  { id: "Sourcegraph.cody-ai", name: "Cody AI", vendor: "Sourcegraph" },
  { id: "saoudrizwan.claude-dev", name: "Cline", vendor: "Cline Bot" },
];

const NOTICE_SHOWN_KEY = "keymontr.aiAssistantNoticeShown";

export class AIAssistantDetector {
  private readonly agentsFilePath: string;
  private agentsCache: AIAgent[] | null = null;

  constructor(private readonly context: vscode.ExtensionContext) {
    this.agentsFilePath = path.join(
      context.extensionPath,
      "agents",
      "ai-agents.json",
    );
  }

  /**
   * Returns the full registry of known AI assistants.
   * Loads from agents/ai-agents.json, falling back to the built-in list.
   */
  public getAllKnownAgents(): AIAgent[] {
    if (this.agentsCache !== null) {
      return this.agentsCache;
    }

    try {
      const raw = fs.readFileSync(this.agentsFilePath, "utf-8");
      const parsed = JSON.parse(raw) as { agents?: unknown };
      const agents = parsed.agents;

      if (Array.isArray(agents)) {
        const validated = agents.filter(
          (entry): entry is AIAgent =>
            typeof entry === "object" &&
            entry !== null &&
            typeof (entry as AIAgent).id === "string" &&
            typeof (entry as AIAgent).name === "string",
        );
        this.agentsCache = validated.length > 0 ? validated : FALLBACK_AGENTS;
      } else {
        this.agentsCache = FALLBACK_AGENTS;
      }
    } catch {
      // Registry unreadable/corrupt — never let detection crash the extension.
      this.agentsCache = FALLBACK_AGENTS;
    }

    return this.agentsCache;
  }

  /**
   * Returns agents that are installed (and enabled) in the current VS Code,
   * with a flag indicating whether each has been activated in this session.
   */
  public getInstalledAssistants(): DetectedAIAgent[] {
    return this.getAllKnownAgents().map((agent) => {
      const extension = vscode.extensions.getExtension(agent.id);
      return {
        ...agent,
        installed: extension !== undefined,
        active: extension?.isActive === true,
      };
    });
  }

  /**
   * Returns agents that are currently active (running alongside Keymontr).
   * Used for the informational notice — only genuinely running assistants
   * trigger the reminder, not merely installed ones.
   */
  public detectActiveAssistants(): DetectedAIAgent[] {
    return this.getInstalledAssistants().filter((agent) => agent.active);
  }

  /**
   * Shows the informational notice if an AI assistant is detected
   * and the notice has not been shown in this session.
   */
  public async showNoticeIfNeeded(): Promise<void> {
    // Only show once per session
    const alreadyShown = this.context.workspaceState.get<boolean>(
      NOTICE_SHOWN_KEY,
      false,
    );

    if (alreadyShown) {
      return;
    }

    const detected = this.detectActiveAssistants();

    if (detected.length === 0) {
      return;
    }

    const names = detected.map((d) => d.name).join(", ");

    const action = await vscode.window.showInformationMessage(
      `Keymontr: ${names} detected. ` +
        `Be mindful when sharing sensitive files or credentials with AI assistants.`,
      "Got it",
      "Learn More",
    );

    await this.context.workspaceState.update(NOTICE_SHOWN_KEY, true);

    if (action === "Learn More") {
      await vscode.env.openExternal(
        vscode.Uri.parse(
          "https://github.com/CoreCoderX/Keymontr#ai-assistant-notice",
        ),
      );
    }
  }
}