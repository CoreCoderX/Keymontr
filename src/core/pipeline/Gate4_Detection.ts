import { Layer1_RegexEngine } from "../layers/Layer1_RegexEngine.js";
import { Layer2_EntropyEngine } from "../layers/Layer2_EntropyEngine.js";
import { Layer3_ContextEngine } from "../layers/Layer3_ContextEngine.js";
import { Layer4_StringGroupEngine } from "../layers/Layer4_StringGroupEngine.js";
import { Layer5_FileContextScorer } from "../layers/Layer5_FileContextScorer.js";
import {
  SecretCandidate,
  RegexLayerResult,
  EntropyLayerResult,
  ContextLayerResult,
  StringGroupLayerResult,
  FileContextLayerResult,
  FileRiskLevel,
} from "../types/DetectionResult.js";

/**
 * Gate 4 — Multi-Layer Detection Engine
 *
 * Orchestrates all five detection layers and collects their results.
 * Does NOT compute the final confidence score (that is Gate 6's job).
 *
 * This gate is a pure aggregator — it runs each layer independently
 * and returns all results for Gate 6 to combine.
 */

export interface Gate4Result {
  layer1: RegexLayerResult;
  layer2: EntropyLayerResult;
  layer3: ContextLayerResult;
  layer4: StringGroupLayerResult;
  layer5: FileContextLayerResult;
  ruleEntropyThreshold: number;
}

export class Gate4_Detection {
  constructor(
    private readonly layer1: Layer1_RegexEngine,
    private readonly layer2: Layer2_EntropyEngine,
    private readonly layer3: Layer3_ContextEngine,
    private readonly layer4: Layer4_StringGroupEngine,
    private readonly layer5: Layer5_FileContextScorer,
  ) {}

  /**
   * Runs all five detection layers on a candidate and returns aggregated results.
   *
   * @param candidate - The secret candidate
   * @param fileRiskLevel - Risk level from Gate 0
   * @param isLineInComment - Whether the candidate line is in a comment
   */
  public evaluate(
    candidate: SecretCandidate,
    fileRiskLevel: FileRiskLevel,
    isLineInComment: boolean,
  ): Gate4Result {
    // Layer 1: Regex detection
    const layer1Result = this.layer1.evaluate(candidate);

    // Layer 2: Entropy analysis
    // Use rule-specific threshold if a rule was matched, otherwise default
    const entropyThreshold =
      layer1Result.matched && layer1Result.ruleId !== undefined
        ? this.layer1.getEntropyThresholdForRule(layer1Result.ruleId)
        : undefined;

    const layer2Result = this.layer2.evaluate(candidate, entropyThreshold);

    // Layer 3: Context analysis (identifier-based)
    const layer3Result = this.layer3.evaluate(candidate);

    // Layer 4: StringGroup analysis (paper implementation)
    const layer4Result = this.layer4.evaluate(candidate);

    // Layer 5: File context scoring
    const layer5Result = this.layer5.evaluate(
      candidate,
      fileRiskLevel,
      isLineInComment,
    );

    return {
      layer1: layer1Result,
      layer2: layer2Result,
      layer3: layer3Result,
      layer4: layer4Result,
      layer5: layer5Result,
      ruleEntropyThreshold: entropyThreshold ?? 3.0,
    };
  }
}
