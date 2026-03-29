/**
 * Tests for scanner.ts rule-type dispatch paths that cannot be reached with the
 * production RULES set (json-path placeholder, default branch, invalid regex,
 * generic keyword, and note-severity summary counting).
 *
 * The RULES module is mocked at the module level so these tests run in
 * isolation from production rules.
 */

import * as os from "os";
import * as fs from "fs";
import * as path from "path";
import { scan } from "../scanner";

jest.mock("../rules", () => ({
  RULES: [
    {
      id: "TEST-BAD-REGEX",
      name: "Invalid regex rule",
      description: "Rule with invalid regex — scanner must skip it silently",
      defaultSeverity: "error",
      pattern: {
        type: "regex",
        value: "([", // intentionally invalid
        fileTypes: [".ts"],
      },
    },
    {
      id: "TEST-KEYWORD",
      name: "Generic keyword rule",
      description: "Non-MCP-004 keyword rule to exercise the generic keyword path",
      defaultSeverity: "warning",
      pattern: {
        type: "keyword",
        value: "DANGEROUS_MARKER",
        fileTypes: [".ts"],
      },
    },
    {
      id: "TEST-KEYWORD-ABSENT",
      name: "Generic keyword rule (absent)",
      description: "Keyword not present in file — must return no findings",
      defaultSeverity: "warning",
      pattern: {
        type: "keyword",
        value: "this_keyword_is_not_in_any_fixture_xyz",
        fileTypes: [".ts"],
      },
    },
    {
      id: "TEST-JSON-PATH",
      name: "JSON-path rule",
      description: "json-path rule — currently a no-op placeholder",
      defaultSeverity: "note",
      pattern: {
        type: "json-path",
        value: "$.tools[*].name",
        fileTypes: [".json"],
      },
    },
    {
      id: "TEST-NOTE",
      name: "Note severity rule",
      description: "Rule that produces note-severity findings",
      defaultSeverity: "note",
      pattern: {
        type: "regex",
        value: "NOTE_MARKER",
        fileTypes: [".ts"],
      },
    },
  ],
}));

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-rule-types-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("applyRegexRule — invalid regex", () => {
  it("skips a rule whose regex pattern is invalid and returns zero findings", async () => {
    const file = path.join(tmpDir, "test.ts");
    fs.writeFileSync(file, "const x = 1;");
    const result = await scan({ input: file, rules: ["TEST-BAD-REGEX"] });
    expect(result.findings).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });
});

describe("applyKeywordRule — generic keyword path (non-MCP-004)", () => {
  it("detects a keyword presence finding when keyword appears in file", async () => {
    const file = path.join(tmpDir, "test.ts");
    fs.writeFileSync(file, "const cfg = { mode: 'DANGEROUS_MARKER' };");
    const result = await scan({ input: file, rules: ["TEST-KEYWORD"] });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings[0].ruleId).toBe("TEST-KEYWORD");
    expect(result.findings[0].severity).toBe("warning");
    expect(result.findings[0].line).toBeGreaterThan(0);
  });

  it("returns no finding when keyword is absent from file", async () => {
    const file = path.join(tmpDir, "test.ts");
    fs.writeFileSync(file, "const x = 'safe content only';");
    const result = await scan({ input: file, rules: ["TEST-KEYWORD-ABSENT"] });
    expect(result.findings).toHaveLength(0);
  });
});

describe("applyRule — json-path type (placeholder)", () => {
  it("returns no findings for a json-path rule (not yet implemented)", async () => {
    const file = path.join(tmpDir, "test.json");
    fs.writeFileSync(file, JSON.stringify({ tools: [{ name: "foo" }] }));
    const result = await scan({ input: file, rules: ["TEST-JSON-PATH"] });
    expect(result.findings).toHaveLength(0);
  });
});

describe("scan() — note severity summary", () => {
  it("counts note-severity findings in summary.notes", async () => {
    const file = path.join(tmpDir, "test.ts");
    fs.writeFileSync(file, "// NOTE_MARKER: pay attention here");
    const result = await scan({ input: file, rules: ["TEST-NOTE"] });
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.summary.notes).toBe(
      result.findings.filter((f) => f.severity === "note").length,
    );
    expect(result.summary.notes).toBeGreaterThan(0);
    expect(result.summary.errors).toBe(0);
    expect(result.summary.warnings).toBe(0);
  });
});
