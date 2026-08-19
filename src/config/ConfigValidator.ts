export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validates a Keymontr configuration object.
 * Returns detailed errors and warnings for misconfiguration.
 */
export class ConfigValidator {
  public validate(config: unknown): ValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (
      config === null ||
      typeof config !== "object" ||
      Array.isArray(config)
    ) {
      return {
        valid: false,
        errors: ["Configuration must be a JSON object"],
        warnings: [],
      };
    }

    const cfg = config as Record<string, unknown>;

    this.validateVersion(cfg, errors);
    this.validateDetection(cfg, errors, warnings);
    this.validateGit(cfg, errors, warnings);
    this.validateUI(cfg, warnings);
    this.validateIgnore(cfg, warnings);
    this.validateCustomRules(cfg, errors);
    this.validateRemediation(cfg, warnings);

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  private validateVersion(
    cfg: Record<string, unknown>,
    errors: string[],
  ): void {
    const version = cfg["version"];
    if (version !== undefined && version !== 1) {
      errors.push(
        `Unsupported configuration version: ${JSON.stringify(version)}. Expected: 1`,
      );
    }
  }

  private validateDetection(
    cfg: Record<string, unknown>,
    errors: string[],
    warnings: string[],
  ): void {
    const detection = cfg["detection"];
    if (detection === undefined) {
      return;
    }

    if (typeof detection !== "object" || Array.isArray(detection)) {
      errors.push("detection must be an object");
      return;
    }

    const det = detection as Record<string, unknown>;

    const sensitivity = det["sensitivity"];
    if (sensitivity !== undefined) {
      const isKnownSensitivity =
        typeof sensitivity === "string" &&
        ["strict", "balanced", "relaxed"].includes(sensitivity);
      if (!isKnownSensitivity) {
        errors.push(
          "detection.sensitivity must be 'strict', 'balanced', or 'relaxed'",
        );
      }
    }

    if (det["minimumConfidenceToWarn"] !== undefined) {
      const val = Number(det["minimumConfidenceToWarn"]);
      if (isNaN(val) || val < 0.1 || val > 1.0) {
        errors.push(
          "detection.minimumConfidenceToWarn must be a number between 0.1 and 1.0",
        );
      }
      if (val > 0.8) {
        warnings.push(
          "detection.minimumConfidenceToWarn is very high — many real secrets may go undetected",
        );
      }
    }

    if (det["debounceMs"] !== undefined) {
      const val = Number(det["debounceMs"]);
      if (isNaN(val) || val < 0 || val > 5000) {
        errors.push("detection.debounceMs must be a number between 0 and 5000");
      }
    }

    if (det["weights"] !== undefined) {
      this.validateWeights(det["weights"], errors, warnings);
    }
  }

  private validateWeights(
    weights: unknown,
    errors: string[],
    warnings: string[],
  ): void {
    if (
      typeof weights !== "object" ||
      Array.isArray(weights) ||
      weights === null
    ) {
      errors.push("detection.weights must be an object");
      return;
    }

    const w = weights as Record<string, unknown>;
    const fields = [
      "regex",
      "entropy",
      "context",
      "stringGroup",
      "fileContext",
    ];
    let total = 0;

    for (const field of fields) {
      if (w[field] !== undefined) {
        const val = Number(w[field]);
        if (isNaN(val) || val < 0 || val > 1) {
          errors.push(
            `detection.weights.${field} must be a number between 0 and 1`,
          );
        } else {
          total += val;
        }
      }
    }

    const allDefined = fields.every((f) => w[f] !== undefined);
    if (allDefined && Math.abs(total - 1.0) > 0.01) {
      warnings.push(
        `detection.weights sum to ${total.toFixed(2)}, expected 1.00. Scores will be normalized.`,
      );
    }
  }

  private validateGit(
    cfg: Record<string, unknown>,
    errors: string[],
    warnings: string[],
  ): void {
    const git = cfg["git"];
    if (git === undefined) {
      return;
    }

    if (typeof git !== "object" || Array.isArray(git)) {
      errors.push("git must be an object");
      return;
    }

    const g = git as Record<string, unknown>;

    if (
      g["blockCommitOnCritical"] === false &&
      g["blockCommitOnHigh"] === false
    ) {
      warnings.push(
        "Both blockCommitOnCritical and blockCommitOnHigh are false. " +
          "Git protection is effectively disabled for severe findings.",
      );
    }
  }

  private validateUI(cfg: Record<string, unknown>, warnings: string[]): void {
    const ui = cfg["ui"];
    if (ui === undefined) {
      return;
    }

    if (typeof ui !== "object" || Array.isArray(ui)) {
      warnings.push("ui must be an object — using defaults");
      return;
    }

    const u = ui as Record<string, unknown>;
    const soundTheme = u["soundTheme"];
    if (soundTheme !== undefined) {
      const isKnownSoundTheme =
        typeof soundTheme === "string" &&
        ["default", "minimal", "none"].includes(soundTheme);
      if (!isKnownSoundTheme) {
        warnings.push(
          "ui.soundTheme should be 'default', 'minimal', or 'none'",
        );
      }
    }
  }

  private validateIgnore(
    cfg: Record<string, unknown>,
    warnings: string[],
  ): void {
    const ignore = cfg["ignore"];
    if (ignore === undefined) {
      return;
    }

    if (typeof ignore !== "object" || Array.isArray(ignore)) {
      warnings.push("ignore must be an object — using defaults");
      return;
    }

    const ig = ignore as Record<string, unknown>;
    if (ig["paths"] !== undefined && !Array.isArray(ig["paths"])) {
      warnings.push("ignore.paths must be an array — using empty array");
    }
    if (ig["patterns"] !== undefined && !Array.isArray(ig["patterns"])) {
      warnings.push("ignore.patterns must be an array — using empty array");
    }
  }

  private validateCustomRules(
    cfg: Record<string, unknown>,
    errors: string[],
  ): void {
    const rules = cfg["customRules"];
    if (rules === undefined) {
      return;
    }

    if (!Array.isArray(rules)) {
      errors.push("customRules must be an array");
      return;
    }

    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i] as Record<string, unknown>;
      const id = rule["id"];
      if (typeof id !== "string" || id.length === 0) {
        errors.push(`customRules[${i}]: id is required and must be a string`);
      }
      const regex = rule["regex"];
      if (typeof regex !== "string" || regex.length === 0) {
        errors.push(
          `customRules[${i}]: regex is required and must be a string`,
        );
      } else {
        try {
          new RegExp(regex);
        } catch {
          errors.push(
            `customRules[${i}]: regex is not a valid regular expression`,
          );
        }
      }
    }
  }

  private validateRemediation(
    cfg: Record<string, unknown>,
    warnings: string[],
  ): void {
    const rem = cfg["remediation"];
    if (rem === undefined) {
      return;
    }

    if (typeof rem !== "object" || Array.isArray(rem)) {
      warnings.push("remediation must be an object — using defaults");
      return;
    }

    const r = rem as Record<string, unknown>;
    if (
      r["preferredEnvFileName"] !== undefined &&
      typeof r["preferredEnvFileName"] !== "string"
    ) {
      warnings.push(
        "remediation.preferredEnvFileName must be a string — using '.env'",
      );
    }
  }
}
