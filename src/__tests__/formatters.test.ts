import Ajv from "ajv";
import { ScanResult } from "../types";
import { toSarif } from "../formatters/sarif";
import { toText } from "../formatters/text";

/** Minimal SARIF 2.1.0 structural schema for validation. */
const SARIF_SCHEMA = {
  type: "object",
  required: ["$schema", "version", "runs"],
  properties: {
    $schema: { type: "string" },
    version: { type: "string", const: "2.1.0" },
    runs: {
      type: "array",
      minItems: 1,
      items: {
        type: "object",
        required: ["tool", "results"],
        properties: {
          tool: {
            type: "object",
            required: ["driver"],
            properties: {
              driver: {
                type: "object",
                required: ["name", "version", "rules"],
                properties: {
                  name: { type: "string" },
                  version: { type: "string" },
                  rules: { type: "array" },
                },
              },
            },
          },
          results: {
            type: "array",
            items: {
              type: "object",
              required: ["ruleId", "level", "message", "locations"],
              properties: {
                ruleId: { type: "string" },
                level: {
                  type: "string",
                  enum: ["error", "warning", "note", "none"],
                },
                message: {
                  type: "object",
                  required: ["text"],
                  properties: { text: { type: "string" } },
                },
                locations: {
                  type: "array",
                  minItems: 1,
                  items: {
                    type: "object",
                    required: ["physicalLocation"],
                    properties: {
                      physicalLocation: {
                        type: "object",
                        required: ["artifactLocation"],
                        properties: {
                          artifactLocation: {
                            type: "object",
                            required: ["uri"],
                            properties: { uri: { type: "string" } },
                          },
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
};

/** A minimal ScanResult with findings for testing. */
const MOCK_RESULT: ScanResult = {
  target: "/tmp/test-project",
  startedAt: "2026-03-29T10:00:00.000Z",
  finishedAt: "2026-03-29T10:00:01.000Z",
  filesScanned: 3,
  errors: [],
  summary: { errors: 1, warnings: 1, notes: 0 },
  findings: [
    {
      ruleId: "MCP-001",
      message: "MCP-001: Prompt injection via tool description",
      severity: "error",
      filePath: "/tmp/test-project/src/server.ts",
      line: 42,
      column: 5,
      snippet: "ignore previous instructions",
    },
    {
      ruleId: "MCP-004",
      message: "MCP-004: Unvalidated tool input schema",
      severity: "warning",
      filePath: "/tmp/test-project/schema.json",
      snippet: "additionalProperties",
    },
  ],
};

const EMPTY_RESULT: ScanResult = {
  target: "/tmp/clean-project",
  startedAt: "2026-03-29T10:00:00.000Z",
  finishedAt: "2026-03-29T10:00:00.100Z",
  filesScanned: 5,
  errors: [],
  summary: { errors: 0, warnings: 0, notes: 0 },
  findings: [],
};

const ajv = new Ajv({ strict: false });

describe("toSarif()", () => {
  it("produces a valid SARIF 2.1.0 structure", () => {
    const sarif = toSarif(MOCK_RESULT);
    const validate = ajv.compile(SARIF_SCHEMA);
    const valid = validate(sarif);
    if (!valid) {
      console.error(ajv.errorsText(validate.errors));
    }
    expect(valid).toBe(true);
  });

  it("sets the correct $schema URL", () => {
    const sarif = toSarif(MOCK_RESULT);
    expect(sarif.$schema).toContain("sarif-2.1.0");
  });

  it("sets version to 2.1.0", () => {
    const sarif = toSarif(MOCK_RESULT);
    expect(sarif.version).toBe("2.1.0");
  });

  it("produces one run", () => {
    const sarif = toSarif(MOCK_RESULT);
    expect(sarif.runs).toHaveLength(1);
  });

  it("driver name is mcp-scan", () => {
    const sarif = toSarif(MOCK_RESULT);
    expect(sarif.runs[0].tool.driver.name).toBe("mcp-scan");
  });

  it("maps severity error correctly", () => {
    const sarif = toSarif(MOCK_RESULT);
    const errorResult = sarif.runs[0].results.find((r) => r.ruleId === "MCP-001");
    expect(errorResult?.level).toBe("error");
  });

  it("maps severity warning correctly", () => {
    const sarif = toSarif(MOCK_RESULT);
    const warnResult = sarif.runs[0].results.find((r) => r.ruleId === "MCP-004");
    expect(warnResult?.level).toBe("warning");
  });

  it("includes line numbers in region when present", () => {
    const sarif = toSarif(MOCK_RESULT);
    const result = sarif.runs[0].results.find((r) => r.ruleId === "MCP-001");
    const region = result?.locations[0].physicalLocation.region;
    expect(region?.startLine).toBe(42);
    expect(region?.startColumn).toBe(5);
  });

  it("omits region when line is undefined", () => {
    const sarif = toSarif(MOCK_RESULT);
    const result = sarif.runs[0].results.find((r) => r.ruleId === "MCP-004");
    const region = result?.locations[0].physicalLocation.region;
    expect(region).toBeUndefined();
  });

  it("includes only rules that fired", () => {
    const sarif = toSarif(MOCK_RESULT);
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r) => r.id);
    expect(ruleIds).toContain("MCP-001");
    expect(ruleIds).toContain("MCP-004");
    // Rules that did NOT fire should not be in the descriptor list
    expect(ruleIds).not.toContain("MCP-002");
  });

  it("produces valid SARIF for empty results", () => {
    const sarif = toSarif(EMPTY_RESULT);
    const validate = ajv.compile(SARIF_SCHEMA);
    expect(validate(sarif)).toBe(true);
    expect(sarif.runs[0].results).toHaveLength(0);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(0);
  });

  it("location URIs use file:// scheme", () => {
    const sarif = toSarif(MOCK_RESULT);
    const firstUri = sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
    expect(firstUri).toMatch(/^file:\/\//);
  });
});

describe("toText()", () => {
  it("includes the target path in output", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("/tmp/test-project");
  });

  it("includes files scanned count", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("3 file");
  });

  it("shows ERROR label for error severity", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("[ERROR]");
  });

  it("shows WARNING label for warning severity", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("[WARNING]");
  });

  it("shows rule ID in output", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("MCP-001");
    expect(text).toContain("MCP-004");
  });

  it("shows file path with line number when present", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("server.ts:42");
  });

  it("shows snippet when available", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("ignore previous instructions");
  });

  it("shows summary line", () => {
    const text = toText(MOCK_RESULT, false);
    expect(text).toContain("1 error");
    expect(text).toContain("1 warning");
  });

  it("shows no findings message for clean result", () => {
    const text = toText(EMPTY_RESULT, false);
    expect(text).toContain("No findings");
  });

  it("shows scan errors when present", () => {
    const resultWithErrors: ScanResult = {
      ...MOCK_RESULT,
      errors: ["Could not read file: /tmp/bad.ts"],
    };
    const text = toText(resultWithErrors, false);
    expect(text).toContain("Scan errors:");
    expect(text).toContain("/tmp/bad.ts");
  });
});
