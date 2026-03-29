import * as path from "path";
import { scan } from "../scanner";

const FIXTURES_DIR = path.resolve(__dirname, "../../tests/fixtures");

describe("scan()", () => {
  it("returns a ScanResult with required fields", async () => {
    const result = await scan({ input: FIXTURES_DIR });
    expect(result).toHaveProperty("target");
    expect(result).toHaveProperty("startedAt");
    expect(result).toHaveProperty("finishedAt");
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("filesScanned");
    expect(result).toHaveProperty("errors");
    expect(result).toHaveProperty("summary");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(typeof result.filesScanned).toBe("number");
  });

  it("scans at least 5 fixture files", async () => {
    const result = await scan({ input: FIXTURES_DIR });
    expect(result.filesScanned).toBeGreaterThanOrEqual(5);
  });

  it("finds issues in vulnerable fixtures", async () => {
    const result = await scan({ input: FIXTURES_DIR });
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it("produces 0 findings for the clean server in isolation", async () => {
    const cleanFile = path.join(FIXTURES_DIR, "clean-server.ts");
    const result = await scan({ input: cleanFile });
    expect(result.findings).toHaveLength(0);
    expect(result.summary.errors).toBe(0);
    expect(result.summary.warnings).toBe(0);
  });

  it("detects MCP-001 (prompt injection) in injection-server.ts", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "injection-server.ts"),
      rules: ["MCP-001"],
    });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP-001");
  });

  it("detects MCP-004 (unvalidated schema) in vulnerable-server.json", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "vulnerable-server.json"),
      rules: ["MCP-004"],
    });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP-004");
  });

  it("detects MCP-006 (SSRF) in ssrf-server.ts", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "ssrf-server.ts"),
      rules: ["MCP-006"],
    });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP-006");
  });

  it("detects MCP-010 (unrestricted filesystem) in ssrf-server.ts", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "ssrf-server.ts"),
      rules: ["MCP-010"],
    });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP-010");
  });

  it("detects MCP-008 (insecure SSE) in multi-issue-server.ts", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "multi-issue-server.ts"),
      rules: ["MCP-008"],
    });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("MCP-008");
  });

  it("multi-issue-server triggers 3+ distinct rules", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "multi-issue-server.ts"),
    });
    const distinctRules = new Set(result.findings.map((f) => f.ruleId));
    expect(distinctRules.size).toBeGreaterThanOrEqual(3);
  });

  it("rule filter limits findings to specified rules only", async () => {
    const result = await scan({
      input: FIXTURES_DIR,
      rules: ["MCP-001"],
    });
    const unexpected = result.findings.filter((f) => f.ruleId !== "MCP-001");
    expect(unexpected).toHaveLength(0);
  });

  it("summary counts match findings array", async () => {
    const result = await scan({ input: FIXTURES_DIR });
    const expectedErrors = result.findings.filter((f) => f.severity === "error").length;
    const expectedWarnings = result.findings.filter((f) => f.severity === "warning").length;
    const expectedNotes = result.findings.filter((f) => f.severity === "note").length;
    expect(result.summary.errors).toBe(expectedErrors);
    expect(result.summary.warnings).toBe(expectedWarnings);
    expect(result.summary.notes).toBe(expectedNotes);
  });

  it("line numbers are present and reasonable for regex findings", async () => {
    const result = await scan({
      input: path.join(FIXTURES_DIR, "injection-server.ts"),
      rules: ["MCP-001"],
    });
    for (const finding of result.findings) {
      if (finding.line !== undefined) {
        expect(finding.line).toBeGreaterThan(0);
        expect(finding.line).toBeLessThan(100); // fixture file is small
      }
    }
  });

  it("at least 5 distinct rules trigger across all fixtures", async () => {
    const result = await scan({ input: FIXTURES_DIR });
    const distinctRules = new Set(result.findings.map((f) => f.ruleId));
    expect(distinctRules.size).toBeGreaterThanOrEqual(5);
  });

  it("throws if input path does not exist", async () => {
    await expect(scan({ input: "/nonexistent/path/that/does/not/exist" })).rejects.toThrow(
      "Input path does not exist",
    );
  });
});
