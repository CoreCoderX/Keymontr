#!/usr/bin/env node
/**
 * Pre-commit Scanner — CLI entry point.
 *
 * This script is invoked by the Git pre-commit hook.
 * It initializes the detection pipeline and scans staged files.
 *
 * Exit codes:
 *   0 = No blocking secrets found — commit allowed
 *   1 = Blocking secrets found — commit rejected
 *   2 = Scanner error — commit allowed (fail-open to not block legitimate work)
 */

import * as path from "path";
import * as fs from "fs";
import { DatabaseManager } from "../database/DatabaseManager.js";
import { ConfigurationManager } from "../config/ConfigurationManager.js";
import { Pipeline } from "../core/pipeline/Pipeline.js";
import { Gate8_DeveloperMemory } from "../core/pipeline/Gate8_DeveloperMemory.js";
import { PreCommitScanner } from "./PreCommitScanner.js";
import { CommitBlocker } from "./CommitBlocker.js";

async function main(): Promise<void> {
  // Determine workspace root (where .git is)
  const workspaceRoot = findGitRoot(process.cwd());

  if (workspaceRoot === null) {
    process.stderr.write(
      "[Keymontr] Could not find Git root. Allowing commit.\n",
    );
    process.exit(0);
  }

  // Determine extension root (where databases live)
  // In production, the script is in dist/ and databases are at extension root
  const extensionRoot = path.resolve(__dirname, "..", "..");

  // Validate databases exist
  const db1Path = path.join(
    extensionRoot,
    "regex",
    "assets",
    "gitleaks-rules.json",
  );
  const db2Path = path.join(
    extensionRoot,
    "stringgroup",
    "assets",
    "keyword-index.json",
  );

  if (!fs.existsSync(db1Path) || !fs.existsSync(db2Path)) {
    process.stderr.write(
      "[Keymontr] Database files not found. Allowing commit.\n",
    );
    process.exit(0);
  }

  try {
    // Initialize databases
    const dbManager = DatabaseManager.getInstance();
    await dbManager.initialize(extensionRoot);

    // Load configuration
    const configManager = new ConfigurationManager();
    configManager.load(workspaceRoot);
    const config = configManager.getConfig();

    // Initialize pipeline
    const gate8 = new Gate8_DeveloperMemory();
    const pipeline = new Pipeline(dbManager, configManager, gate8);

    // Run pre-commit scan
    const scanner = new PreCommitScanner(pipeline, workspaceRoot, config);
    const result = scanner.scan();

    // Format and output results
    const blocker = new CommitBlocker();
    const message = blocker.formatBlockMessage(result);

    if (result.blocked) {
      process.stderr.write(message);
      process.exit(1);
    } else {
      process.stdout.write(message);
      process.exit(0);
    }
  } catch (err) {
    process.stderr.write(
      `[Keymontr] Scanner error: ${String(err)}\nAllowing commit (fail-open).\n`,
    );
    // Fail-open: do not block commits if the scanner itself crashes
    process.exit(0);
  }
}

/**
 * Walks up the directory tree to find the Git root.
 */
function findGitRoot(startDir: string): string | null {
  let current = startDir;

  for (let i = 0; i < 20; i++) {
    const gitPath = path.join(current, ".git");
    if (fs.existsSync(gitPath)) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }

  return null;
}

void main();
