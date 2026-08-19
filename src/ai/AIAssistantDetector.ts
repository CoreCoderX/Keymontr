import * as vscode from "vscode";

/**
 * AIAssistantDetector — Detects known AI coding assistant extensions.
 *
 * This is purely INFORMATIONAL. It does NOT block or interfere with
 * any AI assistant. It only shows a one-time notice if an AI assistant
 * is detected running alongside Keymontr.
 *
 * The notice reminds developers to be mindful about sharing
 * sensitive files or credentials with AI assistants.
 */

const KNOWN_AI_ASSISTANT_EXTENSIONS: Array<{
  id: string;
  name: string;
}> = [
  { id: "github.copilot", name: "GitHub Copilot" },
  { id: "github.copilot-chat", name: "GitHub Copilot Chat" },
  {
    id: "amazonwebservices.codewhisperer-for-command-line-companion",
    name: "AWS CodeWhisperer",
  },
  { id: "amazonwebservices.aws-toolkit-vscode", name: "AWS Toolkit" },
  { id: "tabnine.tabnine-vscode", name: "Tabnine" },
  { id: "codeium.codeium", name: "Codeium" },
  { id: "continue.continue", name: "Continue" },
  { id: "sourcegraph.cody-ai", name: "Cody AI" },
  { id: "cursor.ai", name: "Cursor AI" },
  { id: "supermaven.supermaven", name: "Supermaven" },
];

const NOTICE_SHOWN_KEY = "keymontr.aiAssistantNoticeShown";

export class AIAssistantDetector {
  constructor(private readonly context: vscode.ExtensionContext) {}

  /**
   * Detects any active AI assistant extensions.
   * Returns the list of detected assistants.
   */
  public detectActiveAssistants(): Array<{ id: string; name: string }> {
    return KNOWN_AI_ASSISTANT_EXTENSIONS.filter((ext) => {
      const extension = vscode.extensions.getExtension(ext.id);
      return extension?.isActive === true;
    });
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
