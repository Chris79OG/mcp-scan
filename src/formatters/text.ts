import { ScanResult, Finding, Remediation } from "../types";
import { formatTrustScore } from "../trust-score";

/** ANSI color codes for terminal output. */
const COLORS = {
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  green: "\x1b[32m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
} as const;

type ColorMap = typeof COLORS;
type NoColor = Record<keyof ColorMap, "">;

/** Format remediation guidance as indented text lines. */
function formatRemediation(
  remediation: Remediation,
  color: ColorMap | NoColor,
): string {
  const lines: string[] = [];
  lines.push(
    `  ${color.bold}Remediation:${color.reset} ${remediation.summary}`,
  );
  remediation.steps.forEach((step, i) => {
    lines.push(`    ${color.gray}${i + 1}.${color.reset} ${step}`);
  });
  if (remediation.references && remediation.references.length > 0) {
    lines.push(
      `    ${color.gray}See:${color.reset} ${remediation.references[0]}`,
    );
  }
  return lines.join("\n");
}

/**
 * Format a single finding as a human-readable text block.
 *
 * Output format:
 * ```
 * [ERROR] MCP-001: Prompt injection via tool description
 *   → src/tools/weather.ts:42
 *   → "IGNORE PREVIOUS INSTRUCTIONS" detected in tool description
 *   Remediation: Remove embedded instruction-override text...
 *     1. Search the codebase...
 * ```
 */
function formatFinding(finding: Finding, useColor = true): string {
  const color: ColorMap | NoColor = useColor
    ? COLORS
    : { red: "", yellow: "", cyan: "", gray: "", green: "", bold: "", reset: "" };

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
    output += `  ${color.gray}→${color.reset} ${finding.message}\n`;
  }

  if (finding.remediation) {
    output += formatRemediation(finding.remediation, color) + "\n";
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
  const color: ColorMap | NoColor = useColor
    ? COLORS
    : { red: "", yellow: "", cyan: "", gray: "", green: "", bold: "", reset: "" };

  const lines: string[] = [];

  const modeLabel = result.scanMode === "live" ? "live endpoint" : "static";
  lines.push(`${color.bold}mcp-scan${color.reset} — ${result.target} [${modeLabel}]`);

  if (result.scanMode === "live") {
    lines.push(`Probed ${result.filesScanned} endpoint(s) at ${result.startedAt}`);
    if (result.serverCapabilities) {
      const caps = result.serverCapabilities;
      const parts: string[] = [];
      if (caps.serverName)
        parts.push(`${caps.serverName} ${caps.serverVersion ?? ""}`.trim());
      if (caps.protocolVersion) parts.push(`MCP ${caps.protocolVersion}`);
      if (caps.tools) parts.push("tools");
      if (caps.resources) parts.push("resources");
      if (caps.prompts) parts.push("prompts");
      if (parts.length > 0) {
        lines.push(`Server: ${parts.join(" · ")}`);
      }
    }
  } else {
    lines.push(`Scanned ${result.filesScanned} file(s) at ${result.startedAt}`);
  }
  lines.push("");

  if (result.findings.length === 0) {
    lines.push(`${color.green}No findings. ✓${color.reset}`);
  } else {
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
      `Summary: ${color.red}${result.summary.errors} error(s)${color.reset}, ` +
        `${color.yellow}${result.summary.warnings} warning(s)${color.reset}, ` +
        `${result.summary.notes} note(s)`,
    );
  }

  // Trust score section — live scans only
  if (result.trustScore) {
    lines.push("");
    lines.push("─".repeat(60));
    lines.push(formatTrustScore(result.trustScore));
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
