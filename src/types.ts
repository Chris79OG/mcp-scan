/** Severity level for a security finding. */
export type Severity = "error" | "warning" | "note" | "none";

/** Remediation guidance for a finding. */
export interface Remediation {
  /** One-line summary of how to fix the issue. */
  summary: string;
  /** Step-by-step fix instructions. */
  steps: string[];
  /** Optional reference URLs (docs, CVEs, OWASP). */
  references?: string[];
}

/** A single security finding produced by a rule. */
export interface Finding {
  /** The rule that produced this finding. */
  ruleId: string;
  /** Human-readable message explaining the issue. */
  message: string;
  /** Severity level. */
  severity: Severity;
  /** Absolute path to the file containing the finding, or the server URL for live findings. */
  filePath: string;
  /** 1-based line number of the finding, if applicable. */
  line?: number;
  /** 1-based column number of the finding, if applicable. */
  column?: number;
  /** Optional code snippet around the finding location. */
  snippet?: string;
  /** Remediation guidance for this finding. */
  remediation?: Remediation;
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
  /** Default remediation guidance for findings from this rule. */
  remediation?: Remediation;
}

/** Summary counts of findings by severity. */
export interface FindingSummary {
  errors: number;
  warnings: number;
  notes: number;
}

/** Trust score breakdown by security dimension. */
export interface TrustScoreBreakdown {
  /** 0-100: server requires authentication. */
  authentication: number;
  /** 0-100: endpoint uses TLS/HTTPS. */
  encryption: number;
  /** 0-100: tool input schemas are strict. */
  inputValidation: number;
  /** 0-100: rate-limiting headers detected. */
  rateLimiting: number;
  /** 0-100: errors don't leak stack traces. */
  errorHandling: number;
}

/** Weighted trust score for a scanned MCP server. */
export interface TrustScore {
  /** Overall 0-100 score. */
  overall: number;
  /** Per-dimension breakdown. */
  breakdown: TrustScoreBreakdown;
  /** Letter grade: A (90+), B (75+), C (60+), D (45+), F (<45). */
  grade: "A" | "B" | "C" | "D" | "F";
}

/** Capabilities advertised by an MCP server during initialization. */
export interface McpServerCapabilities {
  /** Tools the server supports. */
  tools?: boolean;
  /** Resources the server supports. */
  resources?: boolean;
  /** Prompts the server supports. */
  prompts?: boolean;
  /** Server name from initialize response. */
  serverName?: string;
  /** Server version from initialize response. */
  serverVersion?: string;
  /** Protocol version negotiated. */
  protocolVersion?: string;
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
  /** Number of files examined (static) or endpoints probed (live). */
  filesScanned: number;
  /** Any errors encountered during scanning (non-fatal). */
  errors: string[];
  /** Aggregated counts by severity. */
  summary: FindingSummary;
  /** Trust score (populated for live endpoint scans). */
  trustScore?: TrustScore;
  /** Server capabilities (populated for live endpoint scans). */
  serverCapabilities?: McpServerCapabilities;
  /** Whether this was a live endpoint scan. */
  scanMode?: "static" | "live";
}

/** Output format for scan results. */
export type OutputFormat = "sarif" | "json" | "text";
