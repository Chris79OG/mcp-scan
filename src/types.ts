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

/** A scanning rule definition. */
export interface Rule {
  /** Unique identifier for the rule, e.g. "MCP-A001". */
  id: string;
  /** Short name of the rule. */
  name: string;
  /** Full description of what the rule detects. */
  description: string;
  /** Default severity if not overridden. */
  defaultSeverity: Severity;
  /** Reference URL for more information (e.g. CVE link). */
  helpUri?: string;
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
}

/** Output format for scan results. */
export type OutputFormat = "sarif" | "json" | "text";
