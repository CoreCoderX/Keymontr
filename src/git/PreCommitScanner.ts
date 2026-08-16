import * as path from "path";
import { execSync } from "child_process";
import { Pipeline } from "../core/pipeline/Pipeline.js";
import { PipelineResult } from "../core/types/SecretFinding.js";
import { SeverityLevel } from "../core/types/SeverityLevel.js";
import { SecureShieldConfig } from "../config/ConfigurationManager.js";

export interface PreCommitScanResult {
  blocked: boolean;
  findings: Array<{
    file: string;
    line: number;
    severity: SeverityLevel;
    description: string;
    confidence: number;
  }>;
  scannedFiles: number;
  error?: string;
}

/**
 * PreCommitScanner — Scans staged files before a Git commit.
 *
 * Called from the pre-commit hook script.
 * Reads staged file list from `git diff --cached --name-only`.
 * Runs each staged file through the full detection pipeline.
 * Returns exit code 1 if any blocking findings are found.
 */
export class PreCommitScanner {
  constructor(
    private readonly pipeline: Pipeline,
    private readonly workspaceRoot: string,
    private readonly config: SecureShieldConfig,
  ) {}

  /**
   * Scans all staged files and returns results.
   */
  public scan(): PreCommitScanResult {
    const stagedFiles = this.getStagedFiles();

    if (stagedFiles.length === 0) {
      return { blocked: false, findings: [], scannedFiles: 0 };
    }

    const allFindings: PreCommitScanResult["findings"] = [];

    for (const relativeFile of stagedFiles) {
      const absolutePath = path.join(this.workspaceRoot, relativeFile);

      let content: string;
      try {
        // Read staged content (not working tree) via git show
        content = execSync(`git show :${relativeFile}`, {
          cwd: this.workspaceRoot,
          encoding: "utf-8",
          maxBuffer: 10 * 1024 * 1024, // 10MB max
        });
      } catch {
        // File might be binary or deleted — skip
        continue;
      }

      let result: PipelineResult;
      try {
        result = this.pipeline.run({
          fileUri: absolutePath,
          fileContent: content,
          languageId: this.guessLanguageId(relativeFile),
          triggerType: "pre-commit",
        });
      } catch {
        continue;
      }

      for (const finding of result.findings) {
        allFindings.push({
          file: relativeFile,
          line: finding.candidate.lineNumber + 1, // 1-based for user display
          severity: finding.severity,
          description:
            finding.detection.matchedRuleName ??
            finding.detection.matchedGroup ??
            "Potential secret detected",
          confidence: finding.confidence.finalScore,
        });
      }
    }

    const blocked = this.shouldBlock(allFindings);

    return {
      blocked,
      findings: allFindings,
      scannedFiles: stagedFiles.length,
    };
  }

  /**
   * Determines if the commit should be blocked based on findings.
   */
  private shouldBlock(findings: PreCommitScanResult["findings"]): boolean {
    for (const finding of findings) {
      if (
        finding.severity === SeverityLevel.CRITICAL &&
        this.config.git.blockCommitOnCritical
      ) {
        return true;
      }
      if (
        finding.severity === SeverityLevel.HIGH &&
        this.config.git.blockCommitOnHigh
      ) {
        return true;
      }
      if (
        finding.severity === SeverityLevel.MEDIUM &&
        this.config.git.blockCommitOnMedium
      ) {
        return true;
      }
    }
    return false;
  }

  /**
   * Gets the list of staged files from Git.
   */
  private getStagedFiles(): string[] {
    try {
      const output = execSync(
        "git diff --cached --name-only --diff-filter=ACM",
        {
          cwd: this.workspaceRoot,
          encoding: "utf-8",
        },
      );
      return output
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => f.length > 0);
    } catch {
      return [];
    }
  }

  /**
   * Guesses the VS Code language ID from a file extension.
   */
  private guessLanguageId(filePath: string): string {
    const ext = path.extname(filePath).toLowerCase();
    const map: Record<string, string> = {
      ".ts": "typescript",
      ".tsx": "typescriptreact",
      ".js": "javascript",
      ".jsx": "javascriptreact",
      ".py": "python",
      ".go": "go",
      ".rs": "rust",
      ".java": "java",
      ".cs": "csharp",
      ".php": "php",
      ".rb": "ruby",
      ".sh": "shellscript",
      ".bash": "shellscript",
      ".yaml": "yaml",
      ".yml": "yaml",
      ".json": "json",
      ".toml": "toml",
      ".env": "dotenv",
      ".properties": "properties",
    };
    return map[ext] ?? "plaintext";
  }
}
