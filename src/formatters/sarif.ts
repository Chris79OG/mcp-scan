import * as path from "path";
import * as url from "url";
import { ScanResult, Finding } from "../types";
import { RULES } from "../rules";

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

  return {
    ruleId: finding.ruleId,
    level,
    message: {
      text: finding.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: filePathToUri(finding.filePath),
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

  const ruleDescriptors: SarifReportingDescriptor[] = relevantRules.map((rule) => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.name },
    fullDescription: { text: rule.description },
    defaultConfiguration: {
      level: SEVERITY_MAP[rule.defaultSeverity] ?? "warning",
    },
    ...(rule.helpUri ? { helpUri: rule.helpUri } : {}),
  }));

  const sarifResults = result.findings.map(findingToSarifResult);

  const srcRootUri = filePathToUri(
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
