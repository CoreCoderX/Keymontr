import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { ExtensionContext as MockExtensionContext } from "../../__mocks__/vscode";
import { AIAssistantDetector, type DetectedAIAgent } from "../../../src/ai/AIAssistantDetector";

jest.mock("fs");

const mockedReadFileSync = fs.readFileSync as jest.Mock;

function makeContext(): vscode.ExtensionContext {
  return {
    ...MockExtensionContext,
    extensionPath: "/mock/extension/path",
    workspaceState: {
      get: jest.fn().mockReturnValue(undefined),
      update: jest.fn().mockResolvedValue(undefined),
      keys: jest.fn().mockReturnValue([]),
    },
  } as unknown as vscode.ExtensionContext;
}

const VALID_JSON = JSON.stringify({
  agents: [
    { id: "GitHub.copilot", name: "GitHub Copilot", vendor: "GitHub" },
    { id: "Anthropic.claude-code", name: "Claude Code", vendor: "Anthropic" },
    { id: "broken-entry" }, // no name — must be filtered out
  ],
});

describe("AIAssistantDetector", () => {
  let detector: AIAssistantDetector;

  beforeEach(() => {
    jest.clearAllMocks();
    detector = new AIAssistantDetector(makeContext());
  });

  describe("getAllKnownAgents()", () => {
    it("loads the registry from agents/ai-agents.json", () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      const agents = detector.getAllKnownAgents();
      expect(agents).toHaveLength(2);
      expect(agents[0].id).toBe("GitHub.copilot");
      expect(mockedReadFileSync).toHaveBeenCalledWith(
        path.join("/mock/extension/path", "agents", "ai-agents.json"),
        "utf-8",
      );
    });

    it("falls back to the built-in list when the file is missing", () => {
      mockedReadFileSync.mockImplementation(() => {
        throw new Error("ENOENT");
      });
      const agents = detector.getAllKnownAgents();
      expect(agents.length).toBeGreaterThan(0);
      expect(agents[0].id).toBe("GitHub.copilot");
    });

    it("falls back when the JSON is malformed", () => {
      mockedReadFileSync.mockReturnValue("{ not json");
      const agents = detector.getAllKnownAgents();
      expect(agents.length).toBeGreaterThan(0);
    });

    it("falls back when agents is not an array", () => {
      mockedReadFileSync.mockReturnValue(JSON.stringify({ agents: "nope" }));
      const agents = detector.getAllKnownAgents();
      expect(agents.length).toBeGreaterThan(0);
    });

    it("caches the loaded list", () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      detector.getAllKnownAgents();
      detector.getAllKnownAgents();
      expect(mockedReadFileSync).toHaveBeenCalledTimes(1);
    });
  });

  describe("getInstalledAssistants()", () => {
    it("flags installed and active extensions", () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      (vscode.extensions.getExtension as jest.Mock).mockImplementation(
        (id: string) => (id === "GitHub.copilot" ? { id, isActive: true } : undefined),
      );

      const installed = detector.getInstalledAssistants();
      const copilot = installed.find((a) => a.id === "GitHub.copilot");
      const claude = installed.find((a) => a.id === "Anthropic.claude-code");

      expect(copilot?.installed).toBe(true);
      expect(copilot?.active).toBe(true);
      expect(claude?.installed).toBe(false);
      expect(claude?.active).toBe(false);
    });
  });

  describe("detectActiveAssistants()", () => {
    it("returns only assistants that are actively running", () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      (vscode.extensions.getExtension as jest.Mock).mockImplementation(
        (id: string) => (id === "GitHub.copilot" ? { id, isActive: true } : undefined),
      );

      const active = detector.detectActiveAssistants();
      expect(active).toHaveLength(1);
      expect(active[0].id).toBe("GitHub.copilot");
    });

    it("returns nothing when no assistant is installed", () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      (vscode.extensions.getExtension as jest.Mock).mockReturnValue(undefined);
      expect(detector.detectActiveAssistants()).toHaveLength(0);
    });
  });

  describe("showNoticeIfNeeded()", () => {
    it("skips when the notice was already shown this session", async () => {
      const context = makeContext();
      (context.workspaceState.get as jest.Mock).mockReturnValue(true);
      const d = new AIAssistantDetector(context);
      await d.showNoticeIfNeeded();
      expect(vscode.window.showInformationMessage).not.toHaveBeenCalled();
    });

    it("skips when no AI assistant is active", async () => {
      (vscode.extensions.getExtension as jest.Mock).mockReturnValue(undefined);
      await detector.showNoticeIfNeeded();
      expect(vscode.window.showInformationMessage).not.toHaveBeenCalled();
    });

    it("shows the notice once for active assistants and records it", async () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      (vscode.extensions.getExtension as jest.Mock).mockImplementation(
        (id: string) => (id === "GitHub.copilot" ? { id, isActive: true } : undefined),
      );
      (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue(
        "Got it",
      );

      const context = makeContext();
      const d = new AIAssistantDetector(context);
      await d.showNoticeIfNeeded();

      expect(vscode.window.showInformationMessage).toHaveBeenCalledWith(
        expect.stringContaining("GitHub Copilot"),
        "Got it",
        "Learn More",
      );
      expect(context.workspaceState.update).toHaveBeenCalledWith(
        "keymontr.aiAssistantNoticeShown",
        true,
      );
    });

    it("opens the docs when the user picks Learn More", async () => {
      mockedReadFileSync.mockReturnValue(VALID_JSON);
      (vscode.extensions.getExtension as jest.Mock).mockImplementation(
        (id: string) => (id === "GitHub.copilot" ? { id, isActive: true } : undefined),
      );
      (vscode.window.showInformationMessage as jest.Mock).mockResolvedValue(
        "Learn More",
      );

      const context = makeContext();
      const d = new AIAssistantDetector(context);
      await d.showNoticeIfNeeded();

      expect(context.workspaceState.update).toHaveBeenCalledWith(
        "keymontr.aiAssistantNoticeShown",
        true,
      );
      expect(vscode.env.openExternal).toHaveBeenCalled();
    });
  });

  describe("types", () => {
    it("DetectedAIAgent extends AIAgent with runtime flags", () => {
      const agent: DetectedAIAgent = {
        id: "x.y",
        name: "X",
        installed: true,
        active: false,
      };
      expect(agent.installed).toBe(true);
    });
  });
});