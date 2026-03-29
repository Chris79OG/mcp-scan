/**
 * Tests for the extended static rule set (MCP-011 to MCP-015).
 *
 * Verifies that each new rule exists with required fields, correct severity,
 * and that the pattern matches expected vulnerable code snippets.
 */

import { RULES, getRuleById } from "../rules";
import { scan } from "../scanner";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// ---------------------------------------------------------------------------
// Rule metadata tests
// ---------------------------------------------------------------------------

describe("Extended rules metadata (MCP-011 to MCP-015)", () => {
  const extendedIds = ["MCP-011", "MCP-012", "MCP-013", "MCP-014", "MCP-015"];

  it("all 15 rules are present", () => {
    expect(RULES.length).toBe(15);
  });

  it.each(extendedIds)("%s exists in RULES array", (id) => {
    expect(getRuleById(id)).toBeDefined();
  });

  it.each(extendedIds)("%s has required fields", (id) => {
    const rule = getRuleById(id)!;
    expect(typeof rule.id).toBe("string");
    expect(typeof rule.name).toBe("string");
    expect(typeof rule.description).toBe("string");
    expect(["error", "warning", "note"]).toContain(rule.defaultSeverity);
    expect(rule.pattern).toBeDefined();
    expect(rule.remediation).toBeDefined();
    expect(Array.isArray(rule.remediation!.steps)).toBe(true);
    expect(rule.remediation!.steps.length).toBeGreaterThan(0);
  });

  it("MCP-011 is error severity", () => {
    expect(getRuleById("MCP-011")!.defaultSeverity).toBe("error");
  });

  it("MCP-012 is error severity", () => {
    expect(getRuleById("MCP-012")!.defaultSeverity).toBe("error");
  });

  it("MCP-013 is warning severity", () => {
    expect(getRuleById("MCP-013")!.defaultSeverity).toBe("warning");
  });

  it("MCP-014 is warning severity", () => {
    expect(getRuleById("MCP-014")!.defaultSeverity).toBe("warning");
  });

  it("MCP-015 is warning severity", () => {
    expect(getRuleById("MCP-015")!.defaultSeverity).toBe("warning");
  });
});

// ---------------------------------------------------------------------------
// Fixture-based detection tests
// ---------------------------------------------------------------------------

function withTempDir(content: Record<string, string>, fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mcp-scan-test-"));
  for (const [file, body] of Object.entries(content)) {
    fs.writeFileSync(path.join(dir, file), body, "utf8");
  }
  return fn(dir).finally(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
}

describe("MCP-011 — hardcoded credentials detection", () => {
  it("detects hardcoded API key in .ts file", async () => {
    await withTempDir({
      "config.ts": `const apiKey = "sk-abcdef1234567890abcdef1234567890";\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-011"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-011")).toBe(true);
    });
  });

  it("detects hardcoded password in .js file", async () => {
    await withTempDir({
      "server.js": `const password = "supersecretpassword123!";\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-011"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-011")).toBe(true);
    });
  });

  it("does NOT flag env variable references", async () => {
    await withTempDir({
      "config.ts": `const apiKey = process.env.API_KEY;\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-011"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-011")).toBe(false);
    });
  });
});

describe("MCP-012 — insecure eval detection", () => {
  it("detects eval with user params", async () => {
    await withTempDir({
      "handler.ts": `
async function run(params: Record<string, string>) {
  const result = eval(params.expression);
  return result;
}
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-012"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-012")).toBe(true);
    });
  });

  it("detects new Function with input args", async () => {
    await withTempDir({
      "executor.js": `
const fn = new Function(input.code);
fn();
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-012"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-012")).toBe(true);
    });
  });
});

describe("MCP-013 — cleartext HTTP endpoint detection", () => {
  it("detects http:// endpoint URL in .ts config", async () => {
    await withTempDir({
      "config.ts": `const endpoint = "http://api.production.example.com/mcp";\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-013"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-013")).toBe(true);
    });
  });

  it("does NOT flag localhost http:// URLs", async () => {
    await withTempDir({
      "dev.ts": `const baseUrl = "http://localhost:3000";\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-013"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-013")).toBe(false);
    });
  });

  it("does NOT flag https:// URLs", async () => {
    await withTempDir({
      "prod.ts": `const apiUrl = "https://api.example.com/mcp";\n`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-013"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-013")).toBe(false);
    });
  });
});

describe("MCP-014 — sensitive data in logs detection", () => {
  it("detects console.log with password", async () => {
    await withTempDir({
      "auth.ts": `
function login(password: string) {
  console.log("Logging in with password", password);
}
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-014"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-014")).toBe(true);
    });
  });

  it("detects console.debug with token", async () => {
    await withTempDir({
      "middleware.js": `
function validateToken(token) {
  console.debug("Validating token", token);
}
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-014"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-014")).toBe(true);
    });
  });
});

describe("MCP-015 — path traversal via unsanitized input", () => {
  it("detects path.join with request params", async () => {
    await withTempDir({
      "fileHandler.ts": `
import * as path from "path";
async function readFile(params: { filename: string }) {
  const fullPath = path.join("/data", params.filename);
  return fs.readFile(fullPath);
}
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-015"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-015")).toBe(true);
    });
  });

  it("detects path.resolve with request input", async () => {
    await withTempDir({
      "resource.ts": `
const target = path.resolve("/base", req.query.path);
`,
    }, async (dir) => {
      const result = await scan({ input: dir, rules: ["MCP-015"] });
      expect(result.findings.some((f) => f.ruleId === "MCP-015")).toBe(true);
    });
  });
});
