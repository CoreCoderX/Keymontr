import * as path from "path";
import { Gate0_FileIntelligence } from "./Gate0_FileIntelligence.js";
import { Gate1_PreFilter } from "./Gate1_PreFilter.js";
import { Gate2_PlaceholderElimination } from "./Gate2_PlaceholderElimination.js";
import { Gate3_FormatDisambiguation } from "./Gate3_FormatDisambiguation.js";
import { Gate4_Detection } from "./Gate4_Detection.js";
import { Gate5_Allowlist } from "./Gate5_Allowlist.js";
import { Gate6_ConfidenceAggregator } from "./Gate6_ConfidenceAggregator.js";
import { Gate7_ThresholdFilter } from "./Gate7_ThresholdFilter.js";
import { Gate8_DeveloperMemory } from "./Gate8_DeveloperMemory.js";
import { Layer1_RegexEngine } from "../layers/Layer1_RegexEngine.js";
import { Layer2_EntropyEngine } from "../layers/Layer2_EntropyEngine.js";
import { Layer3_ContextEngine } from "../layers/Layer3_ContextEngine.js";
import { Layer4_StringGroupEngine } from "../layers/Layer4_StringGroupEngine.js";
import { Layer5_FileContextScorer } from "../layers/Layer5_FileContextScorer.js";
import { DatabaseManager } from "../../database/DatabaseManager.js";
import { ConfigurationManager } from "../../config/ConfigurationManager.js";
import {
  PipelineInput,
  FileContext,
  FileLine,
} from "../types/PipelineInput.js";
import { SecretFinding, PipelineResult } from "../types/SecretFinding.js";
import { generateFindingId } from "../utils/HashUtils.js";
import { buildCommentMap } from "../utils/LineClassifier.js";
import { SeverityLevel } from "../types/SeverityLevel.js";
import { FileRiskLevel } from "../types/DetectionResult.js";
import { isGenericRule } from "../../database/CollisionResolver.js";
import { LANGUAGE_KEYWORDS } from "../utils/Tokenizer.js";

/**
 * Pipeline — Main Orchestrator
 *
 * Coordinates all 8 gates and 5 layers into a single detection run.
 * This is the primary entry point for all secret detection.
 *
 * Performance features:
 * - Gate 0 eliminates entire files before any line processing
 * - Gate 1 skips lines with no keyword hits
 * - Comment map is pre-built once per file
 * - Results include timing stats for performance monitoring
 */
export class Pipeline {
  private gate0!: Gate0_FileIntelligence;
  private gate1!: Gate1_PreFilter;
  private gate2!: Gate2_PlaceholderElimination;
  private gate3!: Gate3_FormatDisambiguation;
  private gate4!: Gate4_Detection;
  private gate5!: Gate5_Allowlist;
  private gate6!: Gate6_ConfidenceAggregator;
  private gate7!: Gate7_ThresholdFilter;
  private gate8!: Gate8_DeveloperMemory;

  constructor(
    private readonly dbManager: DatabaseManager,
    private readonly config: ConfigurationManager,
    gate8: Gate8_DeveloperMemory,
  ) {
    this.gate8 = gate8;
    this.initializeGates();
  }

  /**
   * Initializes all gates and layers with their dependencies.
   */
  private initializeGates(): void {
    const cfg = this.config.getConfig();
    const db1 = this.dbManager.getGitleaksDb();
    const db2 = this.dbManager.getStringGroupDb();
    const collisionResolver = this.dbManager.getCollisionResolver();

    // Gate 0
    this.gate0 = new Gate0_FileIntelligence(
      this.config.getEffectiveIgnorePaths(),
    );

    // Layers (needed by Gate 4)
    const layer1 = new Layer1_RegexEngine(db1, collisionResolver);
    const layer2 = new Layer2_EntropyEngine();
    const layer3 = new Layer3_ContextEngine(db2);
    const layer4 = new Layer4_StringGroupEngine();
    const layer5 = new Layer5_FileContextScorer();

    // Gates 1–8
    this.gate1 = new Gate1_PreFilter(db1, db2);
    this.gate2 = new Gate2_PlaceholderElimination();
    this.gate3 = new Gate3_FormatDisambiguation();
    this.gate4 = new Gate4_Detection(layer1, layer2, layer3, layer4, layer5);
    this.gate5 = new Gate5_Allowlist(db1, this.config);
    this.gate6 = new Gate6_ConfidenceAggregator(cfg);
    this.gate7 = new Gate7_ThresholdFilter(cfg);
  }

  /**
   * Runs the full detection pipeline on a file.
   *
   * @param input - Pipeline input (file content, URI, trigger type)
   */
  public run(input: PipelineInput): PipelineResult {
    const startTime = Date.now();
    const skippedByGate: Record<string, number> = {
      gate0: 0,
      gate1: 0,
      gate2: 0,
      gate3: 0,
      gate5: 0,
      gate7: 0,
      gate8: 0,
    };

    // ── Gate 0: File Intelligence ──────────────────────────────────────────
    const gate0Result = this.gate0.assess(input.fileUri);

    if (!gate0Result.shouldScan) {
      skippedByGate["gate0"] = 1;
      return this.emptyResult(input.fileUri, startTime, skippedByGate, 0);
    }

    const fileRiskLevel = gate0Result.riskLevel;

    // ── Build file context ─────────────────────────────────────────────────
    const fileContext = this.buildFileContext(input);
    const commentMap = buildCommentMap(fileContext.lines.map((l) => l.content));

    // Determine which lines to scan
    const linesToScan = this.determineLinesToScan(
      fileContext,
      input.changedLines,
    );

    const findings: SecretFinding[] = [];
    let candidatesEvaluated = 0;

    // ── Process each line ──────────────────────────────────────────────────
    for (const fileLine of linesToScan) {
      const { lineNumber, content } = fileLine;
      const isInComment = commentMap[lineNumber] ?? false;

      // Extract surrounding lines (±5)
      const surroundingLines = this.extractSurroundingLines(
        fileContext.lines,
        lineNumber,
        5,
      );

      // ── Gate 1: Pre-Filter ────────────────────────────────────────────
      const gate1Result = this.gate1.evaluateLine(
        content,
        lineNumber,
        surroundingLines,
        isInComment,
      );

      if (!gate1Result.passed) {
        skippedByGate["gate1"] = (skippedByGate["gate1"] ?? 0) + 1;
        continue;
      }

      // Process each candidate from Gate 1
      for (const candidate of gate1Result.candidates) {
        candidatesEvaluated++;

        // ── Gate 2: Placeholder Elimination ──────────────────────────
        const gate2Result = this.gate2.evaluate(candidate);

        // ── Gate 3: Format Disambiguation ─────────────────────────────
        const gate3Result = this.gate3.evaluate(candidate);

        // ── Gate 4: Multi-Layer Detection ─────────────────────────────
        const gate4Result = this.gate4.evaluate(
          candidate,
          fileRiskLevel,
          isInComment,
        );

        // ── Gate 5: Allowlist ─────────────────────────────────────────
        const gate5Result = this.gate5.evaluate(
          candidate,
          input.fileUri,
          gate4Result.layer1.ruleId,
        );

        if (gate5Result.isAllowlisted && !gate4Result.layer1.isKnownProvider) {
          skippedByGate["gate5"] = (skippedByGate["gate5"] ?? 0) + 1;
        }

        // ── Gate 6: Confidence Aggregation ───────────────────────────
        const confidence = this.gate6.aggregate(
          gate4Result,
          gate2Result,
          gate3Result,
          gate5Result,
        );

        // ── Gate 7: Threshold Filter ──────────────────────────────────
        const gate7Result = this.gate7.evaluate(confidence);

        if (!gate7Result.shouldReport) {
          skippedByGate["gate7"] = (skippedByGate["gate7"] ?? 0) + 1;
          continue;
        }

        const severity = gate7Result.severity as SeverityLevel;

        // ── Gate 8: Developer Memory ──────────────────────────────────
        const gate8Result = this.gate8.check(
          input.fileUri,
          lineNumber,
          content,
          gate4Result.layer1.ruleId,
        );

        if (gate8Result.isSuppressed) {
          skippedByGate["gate8"] = (skippedByGate["gate8"] ?? 0) + 1;
          continue;
        }

        // ── Build finding ─────────────────────────────────────────────
        const finding = this.buildFinding(
          candidate,
          confidence,
          severity,
          gate4Result,
          gate8Result.suppressionKey,
          input,
          fileRiskLevel,
        );

        findings.push(finding);
      }
    }

    const processingTimeMs = Date.now() - startTime;

    return {
      fileUri: input.fileUri,
      scannedAt: new Date(),
      findings,
      stats: {
        linesScanned: linesToScan.length,
        candidatesEvaluated,
        findingsCount: findings.length,
        skippedByGate,
        processingTimeMs,
      },
    };
  }

  /**
   * Builds the FileContext object from pipeline input.
   */
  private buildFileContext(input: PipelineInput): FileContext {
    const rawLines = input.fileContent.split("\n");
    const lines: FileLine[] = rawLines.map((content, index) => ({
      lineNumber: index,
      content,
      isInComment: false, // Will be set by comment map
      isChanged: input.changedLines?.includes(index) ?? true,
    }));

    return {
      fileUri: input.fileUri,
      fileName: path.basename(input.fileUri),
      fileExtension: path.extname(input.fileUri).toLowerCase(),
      languageId: input.languageId,
      triggerType: input.triggerType,
      lines,
      totalLines: lines.length,
    };
  }

  /**
   * Determines which lines to scan based on trigger type.
   * For "typing" trigger with changedLines, only scan changed lines.
   * For all other triggers, scan all lines.
   */
  private determineLinesToScan(
    fileContext: FileContext,
    changedLines?: number[],
  ): FileLine[] {
    if (changedLines !== undefined && changedLines.length > 0) {
      // Expand changed lines to include ±2 for context accuracy
      const expandedSet = new Set<number>();
      for (const ln of changedLines) {
        for (let delta = -2; delta <= 2; delta++) {
          const target = ln + delta;
          if (target >= 0 && target < fileContext.totalLines) {
            expandedSet.add(target);
          }
        }
      }
      return fileContext.lines.filter((l) => expandedSet.has(l.lineNumber));
    }

    return fileContext.lines;
  }

  /**
   * Extracts surrounding lines for context (±windowSize lines).
   */
  private extractSurroundingLines(
    lines: FileLine[],
    lineNumber: number,
    windowSize: number,
  ): string[] {
    const result: string[] = [];

    for (let delta = -windowSize; delta <= windowSize; delta++) {
      if (delta === 0) {
        continue;
      }
      const targetLine = lineNumber + delta;
      if (targetLine >= 0 && targetLine < lines.length) {
        result.push(lines[targetLine]?.content ?? "");
      }
    }

    return result;
  }

  /**
   * Builds a complete SecretFinding from all gate results.
   */
  private buildFinding(
    candidate: {
      value: string;
      lineNumber: number;
      startChar: number;
      endChar: number;
      line: string;
      surroundingLines: string[];
      db1KeywordHits: string[];
      db2IdentifierHits: string[];
    },
    confidence: import("../types/DetectionResult.js").ConfidenceBreakdown,
    severity: SeverityLevel,
    gate4Result: import("./Gate4_Detection.js").Gate4Result,
    suppressionKey: string,
    input: PipelineInput,
    fileRiskLevel: FileRiskLevel,
  ): SecretFinding {
    const ruleId = gate4Result.layer1.ruleId;
    const ruleName = gate4Result.layer1.ruleName;
    const matchedGroup = gate4Result.layer3.matchedGroups[0];

    // Generate env variable name suggestion
    const suggestedEnvKey = this.suggestEnvKey(
      candidate,
      ruleId,
      matchedGroup,
      gate4Result.layer3.contextSignals,
    );

    return {
      id: generateFindingId(),
      candidate,
      confidence,
      severity,
      detection: {
        ...(ruleId !== undefined ? { matchedRuleId: ruleId } : {}),
        ...(ruleName !== undefined ? { matchedRuleName: ruleName } : {}),
        ...(matchedGroup !== undefined ? { matchedGroup } : {}),
        entropyValue: gate4Result.layer2.entropy,
        isKnownProvider: gate4Result.layer1.isKnownProvider,
      },
      remediation: {
        suggestedEnvKey,
        autoFixAvailable: true,
        fixSteps: [
          `Add ${suggestedEnvKey}=<your-value> to .env`,
          `Replace the hardcoded value with process.env.${suggestedEnvKey}`,
          `Ensure .env is listed in .gitignore`,
        ],
        estimatedEffort: "instant",
      },
      suppression: {
        suppressionKey,
        inlineIgnoreComment: "// keymontr-ignore",
        isPermanentlySuppressed: false,
        isSessionSuppressed: false,
      },
      meta: {
        detectedAt: new Date(),
        fileUri: input.fileUri,
        fileName: path.basename(input.fileUri),
        fileRiskLevel,
        languageId: input.languageId,
        triggerType: input.triggerType,
      },
    };
  }

  /**
   * Suggests a descriptive environment variable key name for a finding.
   *
   * Priority:
   *  1. Specific (non-generic) rule ID — e.g. aws-access-token → AWS_ACCESS_TOKEN
   *  2. Assignment identifier on the candidate's own line (camelCase → SNAKE)
   *     — e.g. paymentApiKey → PAYMENT_API_KEY, AZURE_STORAGE_KEY → AZURE_STORAGE_KEY
   *  3. DB2 identifier hits
   *  4. Specific context group (skips Generic Secrets / Common Aliases)
   *  5. SECRET_KEY
   */
  private suggestEnvKey(
    candidate: { line: string; db2IdentifierHits: string[] },
    ruleId?: string,
    matchedGroup?: string,
    contextSignals: Array<{
      group: string;
      distance: number;
    }> = [],
  ): string {
    // 1. Specific rule ID — best name for provider-matched secrets
    if (ruleId !== undefined && !isGenericRule(ruleId)) {
      return ruleId
        .toUpperCase()
        .replace(/-/g, "_")
        .replace(/[^A-Z0-9_]/g, "");
    }

    // 2. Assignment identifier on this line (e.g. `paymentApiKey: "..."`).
    //    `return "..."` must NOT be used — "return" is a language keyword.
    //    Structural keys ("command", "image", ...) are skipped — they are
    //    not secret-related names.
    const assignmentMatch = candidate.line.match(
      /(?:const|let|var|export|private|public|protected|static|final)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]/,
    );
    if (
      assignmentMatch?.[1] !== undefined &&
      !LANGUAGE_KEYWORDS.has(assignmentMatch[1].toLowerCase()) &&
      /(key|token|secret|pass|pwd|cred|auth|api|jwt|salt|hash|sid)/i.test(
        assignmentMatch[1],
      )
    ) {
      return this.toEnvSegment(this.camelToSnake(assignmentMatch[1]));
    }

    // 3. DB2 identifier hits
    if (candidate.db2IdentifierHits.length > 0) {
      const id = candidate.db2IdentifierHits[0];
      if (id !== undefined) {
        return this.toEnvSegment(this.camelToSnake(id));
      }
    }

    // 4. Nearest context signal with a specific (non-generic) group
    //    (distance ≤ 1 — the candidate's own line or an adjacent line).
    const nearSignals = contextSignals
      .filter((signal) => signal.distance <= 1)
      .sort((a, b) => a.distance - b.distance);
    for (const signal of nearSignals) {
      if (
        signal.group !== "Generic Secrets" &&
        signal.group !== "Common Aliases & Casings"
      ) {
        return this.toEnvSegment(signal.group) + "_KEY";
      }
    }

    // 5. Matched group — only when it is genuinely close to the candidate
    //    (otherwise it describes an unrelated neighbor, e.g. a PostgreSQL
    //    block 3 lines above a Redis password).
    if (matchedGroup !== undefined) {
      const nearest = contextSignals
        .filter((signal) => signal.group === matchedGroup)
        .reduce((min, signal) => Math.min(min, signal.distance), 99);
      if (
        nearest <= 1 &&
        matchedGroup !== "Generic Secrets" &&
        matchedGroup !== "Common Aliases & Casings"
      ) {
        return this.toEnvSegment(matchedGroup) + "_KEY";
      }
    }

    return "SECRET_KEY";
  }

  /**
   * Converts camelCase/PascalCase identifiers to snake_case:
   * paymentApiKey → payment_api_key, AWSKeyId → aws_key_id, AZURE_STORAGE_KEY stays.
   */
  private camelToSnake(text: string): string {
    return text
      .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
      .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
      .toLowerCase();
  }

  /**
   * Normalizes arbitrary text (group names, identifiers) into a clean
   * UPPER_SNAKE env var segment. Non-alphanumeric runs (spaces, "&", "/",
   * "-", etc.) collapse to a single underscore and edges are trimmed, so
   * "Key & Token Abbreviations" becomes "KEY_TOKEN_ABBREVIATIONS" (not
   * "KEY__TOKEN_ABBREVIATIONS").
   */
  private toEnvSegment(text: string): string {
    return text
      .toUpperCase()
      .replace(/[^A-Z0-9]+/g, "_")
      .replace(/^_+|_+$/g, "");
  }

  /**
   * Returns an empty pipeline result (when file is excluded or has no findings).
   */
  private emptyResult(
    fileUri: string,
    startTime: number,
    skippedByGate: Record<string, number>,
    linesScanned: number,
  ): PipelineResult {
    return {
      fileUri,
      scannedAt: new Date(),
      findings: [],
      stats: {
        linesScanned,
        candidatesEvaluated: 0,
        findingsCount: 0,
        skippedByGate,
        processingTimeMs: Date.now() - startTime,
      },
    };
  }

  /**
   * Reinitializes all gates (called when config changes at runtime).
   */
  public reinitialize(): void {
    this.initializeGates();
  }
}
