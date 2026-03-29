import { RULES, getRuleById } from "../rules";

describe("getRuleById()", () => {
  it("returns the correct rule for a known valid ID", () => {
    const rule = getRuleById("MCP-001");
    expect(rule).toBeDefined();
    expect(rule!.id).toBe("MCP-001");
    expect(rule!.name).toBe("Prompt injection via tool description");
    expect(rule!.defaultSeverity).toBe("error");
  });

  it("returns undefined for an unrecognized rule ID", () => {
    expect(getRuleById("MCP-999")).toBeUndefined();
  });

  it("returns undefined for an empty string", () => {
    expect(getRuleById("")).toBeUndefined();
  });

  it("can retrieve every rule in RULES by its own ID", () => {
    for (const rule of RULES) {
      expect(getRuleById(rule.id)).toBe(rule);
    }
  });
});

describe("RULES", () => {
  it("exports exactly 10 rules", () => {
    expect(RULES).toHaveLength(10);
  });

  it("all rules have non-empty required fields", () => {
    for (const rule of RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.name).toBeTruthy();
      expect(rule.description).toBeTruthy();
      expect(["error", "warning", "note", "none"]).toContain(rule.defaultSeverity);
      expect(rule.pattern).toBeDefined();
      expect(["regex", "keyword", "json-path"]).toContain(rule.pattern.type);
      expect(Array.isArray(rule.pattern.fileTypes)).toBe(true);
      expect(rule.pattern.fileTypes.length).toBeGreaterThan(0);
    }
  });

  it("all rule IDs follow the MCP-NNN format", () => {
    for (const rule of RULES) {
      expect(rule.id).toMatch(/^MCP-\d{3}$/);
    }
  });

  it("rule IDs are unique", () => {
    const ids = RULES.map((r) => r.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});
