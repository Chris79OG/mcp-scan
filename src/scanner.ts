import * as path from "path";
import * as fs from "fs";
import { Finding, ScanResult, Rule } from "./types";
import { walkDirectory, readFileSafe } from "./walker";
import { RULES } from "./rules";

/** Options for the scan function. */
export interface ScanOptions {
  /** Local directory path to scan. */
  input: string;
  /** Optional list of rule IDs to apply. Defaults to all rules. */
  rules?: string[];
}

/**
 * Apply a regex-type rule to file content.
 *
 * Returns all findings with accurate line numbers.
 */
function applyRegexRule(
  rule: Rule,
  filePath: string,
  content: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split("\n");
  let flags = "g";

  // Extract flags from the pattern value if it starts with (?i)
  let patternValue = rule.pattern.value;
  if (patternValue.startsWith("(?i)")) {
    patternValue = patternValue.slice(4);
    flags = "gi";
  }

  let regex: RegExp;
  try {
    regex = new RegExp(patternValue, flags);
  } catch {
    // Invalid regex — skip rule
    return [];
  }

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    regex.lastIndex = 0;
    const match = regex.exec(line);
    if (match) {
      findings.push({
        ruleId: rule.id,
        message: `${rule.name}: ${rule.description}`,
        severity: rule.defaultSeverity,
        filePath,
        line: lineIndex + 1,
        column: match.index + 1,
        snippet: line.trim(),
      });
    }
  }

  return findings;
}

/**
 * Apply a keyword-type rule to file content.
 *
 * Reports absence of the keyword (e.g. missing `additionalProperties`).
 */
function applyKeywordRule(
  rule: Rule,
  filePath: string,
  content: string,
): Finding[] {
  const keyword = rule.pattern.value;

  // For MCP-004 (additionalProperties): flag JSON schemas that define
  // "properties" but are MISSING "additionalProperties: false"
  if (rule.id === "MCP-004") {
    const hasProperties = content.includes('"properties"') || content.includes("properties:");
    const hasAdditionalPropertiesFalse =
      content.includes('"additionalProperties": false') ||
      content.includes("additionalProperties: false") ||
      content.includes('"additionalProperties":false');

    if (hasProperties && !hasAdditionalPropertiesFalse) {
      return [
        {
          ruleId: rule.id,
          message: `${rule.name}: Schema defines "properties" but is missing \`additionalProperties: false\`. Undeclared properties bypass validation.`,
          severity: rule.defaultSeverity,
          filePath,
          snippet: keyword,
        },
      ];
    }
    return [];
  }

  // Generic keyword presence check
  if (content.includes(keyword)) {
    const lines = content.split("\n");
    const lineIndex = lines.findIndex((l) => l.includes(keyword));
    return [
      {
        ruleId: rule.id,
        message: `${rule.name}: ${rule.description}`,
        severity: rule.defaultSeverity,
        filePath,
        line: lineIndex >= 0 ? lineIndex + 1 : undefined,
        snippet: lineIndex >= 0 ? lines[lineIndex].trim() : undefined,
      },
    ];
  }

  return [];
}

/**
 * Apply a single rule to a single file.
 *
 * Returns an array of findings (may be empty).
 */
function applyRule(rule: Rule, filePath: string, content: string): Finding[] {
  const ext = path.extname(filePath).toLowerCase();

  if (!rule.pattern.fileTypes.includes(ext)) {
    return [];
  }

  switch (rule.pattern.type) {
    case "regex":
      return applyRegexRule(rule, filePath, content);
    case "keyword":
      return applyKeywordRule(rule, filePath, content);
    case "json-path":
      // JSON path evaluation — placeholder for future implementation
      return [];
    default:
      return [];
  }
}

/**
 * Scan a local directory against all (or filtered) MCP CVE detection rules.
 *
 * @param options - Scan options including input path and optional rule filter.
 * @returns A ScanResult with all findings and summary counts.
 */
export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date().toISOString();

  const resolvedInput = path.resolve(options.input);
  if (!fs.existsSync(resolvedInput)) {
    throw new Error(`Input path does not exist: ${resolvedInput}`);
  }

  // Determine which rules to apply
  const activeRuleIds = options.rules ? new Set(options.rules) : null;
  const activeRules = activeRuleIds
    ? RULES.filter((r) => activeRuleIds.has(r.id))
    : RULES;

  const findings: Finding[] = [];
  const errors: string[] = [];
  let filesScanned = 0;

  const stat = fs.statSync(resolvedInput);

  // Handle single-file input
  if (stat.isFile()) {
    filesScanned = 1;
    const content = readFileSafe(resolvedInput);
    if (content !== null) {
      for (const rule of activeRules) {
        findings.push(...applyRule(rule, resolvedInput, content));
      }
    } else {
      errors.push(`Could not read file: ${resolvedInput}`);
    }
  } else {
    // Walk directory
    for (const filePath of walkDirectory(resolvedInput)) {
      filesScanned++;
      const content = readFileSafe(filePath);
      if (content === null) {
        errors.push(`Could not read file: ${filePath}`);
        continue;
      }
      for (const rule of activeRules) {
        findings.push(...applyRule(rule, filePath, content));
      }
    }
  }

  const finishedAt = new Date().toISOString();

  const summary = findings.reduce(
    (acc, f) => {
      if (f.severity === "error") acc.errors++;
      else if (f.severity === "warning") acc.warnings++;
      else if (f.severity === "note") acc.notes++;
      return acc;
    },
    { errors: 0, warnings: 0, notes: 0 },
  );

  return {
    target: resolvedInput,
    startedAt,
    finishedAt,
    findings,
    filesScanned,
    errors,
    summary,
  };
}
