import * as path from "path";
import * as walkerModule from "../walker";
import { scan } from "../scanner";

const FIXTURES_DIR = path.resolve(__dirname, "../../tests/fixtures");
const CLEAN_FILE = path.join(FIXTURES_DIR, "clean-server.ts");
const CLEAN_SCHEMA = path.join(FIXTURES_DIR, "clean-schema.json");

afterEach(() => {
  jest.restoreAllMocks();
});

describe("scan() — MCP-004 schema validation edge cases", () => {
  it("produces no MCP-004 finding when schema has additionalProperties: false", async () => {
    const result = await scan({ input: CLEAN_SCHEMA, rules: ["MCP-004"] });
    const mcp004 = result.findings.filter((f) => f.ruleId === "MCP-004");
    expect(mcp004).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it("produces a MCP-004 finding when schema has properties but no additionalProperties: false", async () => {
    const vulnSchema = path.join(FIXTURES_DIR, "vulnerable-server.json");
    const result = await scan({ input: vulnSchema, rules: ["MCP-004"] });
    const mcp004 = result.findings.filter((f) => f.ruleId === "MCP-004");
    expect(mcp004.length).toBeGreaterThan(0);
  });
});

describe("scan() — empty rule filter", () => {
  it("produces zero findings when rule filter is an empty array", async () => {
    const result = await scan({ input: FIXTURES_DIR, rules: [] });
    expect(result.findings).toHaveLength(0);
    expect(result.filesScanned).toBeGreaterThan(0);
  });
});

describe("scan() — read error handling", () => {
  it("populates errors array when readFileSafe returns null for a single file", async () => {
    jest.spyOn(walkerModule, "readFileSafe").mockReturnValue(null);
    const result = await scan({ input: CLEAN_FILE });
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain("Could not read file");
    expect(result.findings).toHaveLength(0);
    expect(result.filesScanned).toBe(1);
  });

  it("populates errors for each unreadable file during a directory scan", async () => {
    jest.spyOn(walkerModule, "readFileSafe").mockReturnValue(null);
    const result = await scan({ input: FIXTURES_DIR });
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.findings).toHaveLength(0);
    for (const err of result.errors) {
      expect(err).toContain("Could not read file");
    }
  });
});
