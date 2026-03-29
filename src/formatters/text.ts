import { ScanResult, Finding } from "../types";

/** ANSI color codes for terminal output. */
const COLORS = {
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
} as const;

/**
 * Format a single finding as a human-readable text block.
 *
 * Output format:
 * ```
 * [ERROR] MCP-001: Prompt injection via tool description
 *   → src/tools/weather.ts:42
 *   → "IGNORE PREVIOUS INSTRUCTIONS" detected in tool description
 * ```
 */
function formatFinding(finding: Finding, useColor = true): string {
  const color = useColor ? COLORS : { red: "", yellow: "", cyan: "", gray: "", bold: "", reset: "" };

  const severityLabel =
    finding.severity === "error"
      ? `${color.bold}${color.red}[ERROR]${color.reset}`
      : finding.severity === "warning"
        ? `${color.bold}${color.yellow}[WARNING]${color.reset}`
        : `${color.bold}${color.cyan}[NOTE]${color.reset}`;

  const location =
    finding.line !== undefined
      ? `${finding.filePath}:${finding.line}`
      : finding.filePath;

  let output = `${severityLabel} ${color.bold}${finding.ruleId}${color.reset}\n`;
  output += `  ${color.gray}→${color.reset} ${location}\n`;

  if (finding.snippet) {
    output += `  ${color.gray}→${color.reset} ${color.gray}"${finding.snippet}"${color.reset}\n`;
  } else {
    // Fall back to message body
    output += `  ${color.gray}→${color.reset} ${finding.message}\n`;
  }

  return output;
}

/**
 * Format a ScanResult as human-readable text for console output.
 *
 * @param result - The scan result to format.
 * @param useColor - Whether to include ANSI color codes. Defaults to true.
 * @returns Multi-line string suitable for console output.
 */
export function toText(result: ScanResult, useColor = true): string {
  const lines: string[] = [];

  lines.push(`mcp-scan — ${result.target}`);
  lines.push(`Scanned ${result.filesScanned} file(s) at ${result.startedAt}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings. ✓");
  } else {
    // Group findings by severity for readability
    const errors = result.findings.filter((f) => f.severity === "error");
    const warnings = result.findings.filter((f) => f.severity === "warning");
    const notes = result.findings.filter((f) => f.severity === "note");

    const allGroups: Finding[][] = [errors, warnings, notes].filter(
      (g) => g.length > 0,
    );

    for (const group of allGroups) {
      for (const finding of group) {
        lines.push(formatFinding(finding, useColor));
      }
    }

    lines.push(
      `Summary: ${result.summary.errors} error(s), ${result.summary.warnings} warning(s), ${result.summary.notes} note(s)`,
    );
  }

  if (result.errors.length > 0) {
    lines.push("");
    lines.push("Scan errors:");
    for (const err of result.errors) {
      lines.push(`  ! ${err}`);
    }
  }

  return lines.join("\n");
}
