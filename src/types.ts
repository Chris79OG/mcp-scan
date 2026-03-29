/** Severity level for a security finding. */
export type Severity = "error" | "warning" | "note" | "none";

/** A single security finding produced by a rule. */
export interface Finding {
  /** The rule that produced this finding. */
  ruleId: string;
  /** Human-readable message explaining the issue. */
  message: string;
  /** Severity level. */
  severity: Severity;
  /** Absolute path to the file containing the finding. */
  filePath: string;
  /** 1-based line number of the finding, if applicable. */
  line?: number;
  /** 1-based column number of the finding, if applicable. */
  column?: number;
  /** Optional code snippet around the finding location. */
  snippet?: string;
}

/** Pattern type for rule matching. */
export type PatternType = "regex" | "json-path" | "keyword";

/** The detection pattern for a rule. */
export interface RulePattern {
  /** How to evaluate the pattern. */
  type: PatternType;
  /** The pattern value — a regex string, JSONPath expression, or keyword. */
  value: string;
  /** File extensions this pattern applies to (e.g. [".ts", ".json"]). */
  fileTypes: string[];
}

/** A scanning rule definition. */
export interface Rule {
  /** Unique identifier for the rule, e.g. "MCP-001". */
  id: string;
  /** Short name of the rule. */
  name: string;
  /** Full description of what the rule detects. */
  description: string;
  /** Default severity if not overridden. */
  defaultSeverity: Severity;
  /** The detection pattern for this rule. */
  pattern: RulePattern;
  /** Reference URL for more information (e.g. CVE link). */
  helpUri?: string;
}

/** Summary counts of findings by severity. */
export interface FindingSummary {
  errors: number;
  warnings: number;
  notes: number;
}

/** The complete result of a scan operation. */
export interface ScanResult {
  /** Path or URL that was scanned. */
  target: string;
  /** ISO-8601 timestamp when the scan started. */
  startedAt: string;
  /** ISO-8601 timestamp when the scan finished. */
  finishedAt: string;
  /** All findings discovered during the scan. */
  findings: Finding[];
  /** Number of files examined. */
  filesScanned: number;
  /** Any errors encountered during scanning (non-fatal). */
  errors: string[];
  /** Aggregated counts by severity. */
  summary: FindingSummary;
}

/** Output format for scan results. */
export type OutputFormat = "sarif" | "json" | "text";
