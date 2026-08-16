/**
 * What triggered the pipeline run.
 */
export type TriggerType =
  | "typing"
  | "save"
  | "open"
  | "manual-scan"
  | "pre-commit";

/**
 * Input to the main detection pipeline.
 */
export interface PipelineInput {
  /** Absolute file URI path */
  fileUri: string;
  /** Full file content as string */
  fileContent: string;
  /** VS Code language identifier (e.g. "typescript", "python") */
  languageId: string;
  /** What triggered this pipeline run */
  triggerType: TriggerType;
  /**
   * For "typing" trigger — only scan lines that changed.
   * If undefined, all lines are scanned.
   */
  changedLines?: number[];
}

/**
 * A single line extracted from file content with metadata.
 */
export interface FileLine {
  /** 0-based line index */
  lineNumber: number;
  /** Raw string content of the line */
  content: string;
  /** True if this line is within a comment block */
  isInComment: boolean;
  /** True if this line was identified as changed (for incremental scan) */
  isChanged: boolean;
}

/**
 * Represents the file-level context used throughout the pipeline.
 */
export interface FileContext {
  fileUri: string;
  fileName: string;
  fileExtension: string;
  languageId: string;
  triggerType: TriggerType;
  lines: FileLine[];
  totalLines: number;
}
