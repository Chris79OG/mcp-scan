import * as path from "path";
import * as url from "url";
import { ScanResult, Finding } from "../types";
import { RULES } from "../rules";

// Live-scan rules (MCP-L*) are not in the static RULES array; we generate
// descriptors on-the-fly from findings for those.

// eslint-disable-next-line @typescript-eslint/no-require-imports
const pkg = require("../../package.json") as { version: string };

/** Minimal SARIF 2.1.0 type definitions (subset of the full spec). */

export interface SarifArtifactLocation {
  uri: string;
  uriBaseId?: string;
}

export interface SarifRegion {
  startLine?: number;
  startColumn?: number;
  endLine?: number;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifMessage {
  text: string;
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: SarifMessage;
  locations: SarifLocation[];
}

export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: SarifMessage;
  fullDescription: SarifMessage;
  defaultConfiguration: {
    level: "error" | "warning" | "note" | "none";
  };
  helpUri?: string;
  help?: SarifMessage;
}

export interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifReportingDescriptor[];
}

export interface SarifTool {
  driver: SarifToolDriver;
}

export interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
  originalUriBaseIds?: Record<string, SarifArtifactLocation>;
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

/** SARIF severity level values. */
const SEVERITY_MAP: Record<string, "error" | "warning" | "note" | "none"> = {
  error: "error",
  warning: "warning",
  note: "note",
  none: "none",
};

/**
 * Convert a file path to a SARIF-compatible URI (file:// scheme).
 *
 * On Windows, converts backslashes and ensures the drive letter is lowercase.
 */
function filePathToUri(filePath: string): string {
  // Normalize to forward slashes
  const normalized = filePath.replace(/\\/g, "/");
  // url.pathToFileURL handles drive letters on Windows
  return url.pathToFileURL(normalized).href;
}

/**
 * Map a Finding to a SARIF result object.
 * Includes remediation text in the message when available.
 * Handles both local file paths and HTTP URLs as artifact locations.
 */
function findingToSarifResult(finding: Finding): SarifResult {
  const level = SEVERITY_MAP[finding.severity] ?? "warning";

  const region: SarifRegion | undefined =
    finding.line !== undefined
      ? {
          startLine: finding.line,
          startColumn: finding.column ?? 1,
          endLine: finding.line,
        }
      : undefined;

  // If the filePath is already a URL, use it as-is; otherwise convert to file://
  const isUrl =
    finding.filePath.startsWith("http://") ||
    finding.filePath.startsWith("https://");
  const artifactUri = isUrl ? finding.filePath : filePathToUri(finding.filePath);

  // Append remediation summary to the SARIF message when present
  const messageText = finding.remediation
    ? `${finding.message}\n\nRemediation: ${finding.remediation.summary}`
    : finding.message;

  return {
    ruleId: finding.ruleId,
    level,
    message: {
      text: messageText,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: artifactUri,
            uriBaseId: "%SRCROOT%",
          },
          ...(region ? { region } : {}),
        },
      },
    ],
  };
}

/**
 * Convert a ScanResult to a valid SARIF 2.1.0 log.
 *
 * @param result - The scan result to convert.
 * @returns A SARIF log object ready for serialization.
 */
export function toSarif(result: ScanResult): SarifLog {
  // Build the set of rules that actually fired in this scan
  const firedRuleIds = new Set(result.findings.map((f) => f.ruleId));
  const relevantRules = RULES.filter((r) => firedRuleIds.has(r.id));

  // Descriptors for known static rules
  const ruleDescriptors: SarifReportingDescriptor[] = relevantRules.map((rule) => {
    const helpText = rule.remediation
      ? `${rule.remediation.summary}\n\nSteps:\n${rule.remediation.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`
      : undefined;
    return {
      id: rule.id,
      name: rule.name,
      shortDescription: { text: rule.name },
      fullDescription: { text: rule.description },
      defaultConfiguration: {
        level: SEVERITY_MAP[rule.defaultSeverity] ?? "warning",
      },
      ...(rule.helpUri ? { helpUri: rule.helpUri } : {}),
      ...(helpText ? { help: { text: helpText } } : {}),
    };
  });

  // For live rules (MCP-L*) that aren't in the static RULES array, generate
  // minimal descriptors from the findings themselves.
  const staticRuleIds = new Set(RULES.map((r) => r.id));
  const liveRuleIds = [...firedRuleIds].filter((id) => !staticRuleIds.has(id));
  for (const id of liveRuleIds) {
    const sample = result.findings.find((f) => f.ruleId === id);
    if (sample) {
      ruleDescriptors.push({
        id,
        name: id,
        shortDescription: { text: sample.message.split(":")[0] ?? id },
        fullDescription: { text: sample.message },
        defaultConfiguration: {
          level: SEVERITY_MAP[sample.severity] ?? "warning",
        },
      });
    }
  }

  const sarifResults = result.findings.map(findingToSarifResult);

  // For live scans the target is a URL, not a file path
  const isLiveScan = result.scanMode === "live" ||
    result.target.startsWith("http://") ||
    result.target.startsWith("https://");
  const srcRootUri = isLiveScan
    ? result.target
    : filePathToUri(
        path.isAbsolute(result.target) ? path.dirname(result.target) : process.cwd(),
      );

  return {
    $schema:
      "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-scan",
            version: pkg.version,
            informationUri: "https://github.com/syntrophy/mcp-scan",
            rules: ruleDescriptors,
          },
        },
        results: sarifResults,
        originalUriBaseIds: {
          "%SRCROOT%": {
            uri: srcRootUri + "/",
          },
        },
      },
    ],
  };
}
