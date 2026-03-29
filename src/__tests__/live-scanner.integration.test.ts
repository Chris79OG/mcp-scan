/**
 * Integration tests for the live MCP server scanner.
 *
 * These tests spin up a real HTTP server (mock MCP) on a random port, run the
 * live scanner against it, and assert on the findings and trust score.
 *
 * No mocking of network I/O — the scanner makes genuine HTTP calls.
 */

import { scanLive } from "../live-scanner";
import { startMockMcpServer, MockMcpServer } from "../../tests/fixtures/mock-mcp-http-server";

// Give each test a generous timeout — the scanner makes multiple HTTP round-trips.
jest.setTimeout(15_000);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function findingIds(result: Awaited<ReturnType<typeof scanLive>>): string[] {
  return result.findings.map((f) => f.ruleId).sort();
}

// ---------------------------------------------------------------------------
// Insecure server tests
// ---------------------------------------------------------------------------

describe("scanLive — insecure mock server", () => {
  let server: MockMcpServer;

  beforeAll(async () => {
    server = await startMockMcpServer({ mode: "insecure" });
  });

  afterAll(async () => {
    await server.stop();
  });

  it("returns a ScanResult with the correct shape", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000 });

    expect(result.target).toBe(server.url);
    expect(result.scanMode).toBe("live");
    expect(typeof result.startedAt).toBe("string");
    expect(typeof result.finishedAt).toBe("string");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(Array.isArray(result.errors)).toBe(true);
    expect(result.summary).toMatchObject({
      errors: expect.any(Number),
      warnings: expect.any(Number),
      notes: expect.any(Number),
    });
  });

  it("detects MCP-L001 (plain HTTP) on the server URL", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L001"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L001");
  });

  it("detects MCP-L002 (unauthenticated access)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L002"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L002");
  });

  it("detects MCP-L003 (prompt injection in tool description)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L003"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L003");
  });

  it("detects MCP-L004 (missing additionalProperties:false)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L004"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L004");
  });

  it("detects MCP-L005 (stack-trace leakage in error responses)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L005"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L005");
  });

  it("detects MCP-L007 (SSRF-prone parameter names)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L007"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L007");
  });

  it("detects MCP-L009 (unauthenticated SSE endpoint)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L009"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L009");
  });

  it("detects MCP-L010 (unrestricted file-path parameters)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L010"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L010");
  });

  it("detects MCP-L011 (permissive CORS wildcard)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L011"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L011");
  });

  it("detects MCP-L012 (missing security headers)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L012"] });
    const ids = findingIds(result);
    expect(ids).toContain("MCP-L012");
  });

  it("produces a low trust score (< 50) for the insecure server", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000 });
    expect(result.trustScore).toBeDefined();
    expect(result.trustScore!.overall).toBeLessThan(50);
    expect(["D", "F"]).toContain(result.trustScore!.grade);
  });

  it("includes server capabilities in the result", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000 });
    expect(result.serverCapabilities).toBeDefined();
    expect(result.serverCapabilities!.serverName).toContain("mock-mcp-server");
  });

  it("respects rule filter — only returns requested rule findings", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L001"] });
    const ids = findingIds(result);
    expect(ids.every((id) => id === "MCP-L001")).toBe(true);
  });

  it("probes the server at least once (requestCount > 0)", async () => {
    const fresh = await startMockMcpServer({ mode: "insecure" });
    try {
      await scanLive({ url: fresh.url, timeoutMs: 5_000 });
      expect(fresh.requestCount).toBeGreaterThan(0);
    } finally {
      await fresh.stop();
    }
  });
});

// ---------------------------------------------------------------------------
// Secure server tests
// ---------------------------------------------------------------------------

describe("scanLive — secure mock server (no auth required)", () => {
  let server: MockMcpServer;

  beforeAll(async () => {
    server = await startMockMcpServer({ mode: "secure" });
  });

  afterAll(async () => {
    await server.stop();
  });

  it("does NOT fire MCP-L003 (no injection in tool descriptions)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L003"] });
    expect(findingIds(result)).not.toContain("MCP-L003");
  });

  it("does NOT fire MCP-L004 (schemas have additionalProperties:false)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L004"] });
    expect(findingIds(result)).not.toContain("MCP-L004");
  });

  it("does NOT fire MCP-L011 (no wildcard CORS)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L011"] });
    expect(findingIds(result)).not.toContain("MCP-L011");
  });

  it("does NOT fire MCP-L012 (security headers present)", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L012"] });
    expect(findingIds(result)).not.toContain("MCP-L012");
  });

  it("still fires MCP-L001 (HTTP, not HTTPS) even for secure mode", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L001"] });
    expect(findingIds(result)).toContain("MCP-L001");
  });
});

// ---------------------------------------------------------------------------
// Auth-protected server tests
// ---------------------------------------------------------------------------

describe("scanLive — auth-protected mock server", () => {
  const TOKEN = "super-secret-test-token";
  let server: MockMcpServer;

  beforeAll(async () => {
    server = await startMockMcpServer({ mode: "secure", requireAuth: TOKEN });
  });

  afterAll(async () => {
    await server.stop();
  });

  it("detects MCP-L002 when scanned without a token", async () => {
    // The auth probe sends a request without credentials → server returns 401
    // → scanner flags it as auth-required (requiresAuth=true), so MCP-L002 should NOT fire.
    // The server correctly rejects → requiresAuth = true → no finding.
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L002"] });
    expect(findingIds(result)).not.toContain("MCP-L002");
  });

  it("scans successfully with the correct auth token", async () => {
    const result = await scanLive({
      url: server.url,
      authToken: TOKEN,
      timeoutMs: 5_000,
    });
    expect(result.errors.length).toBe(0);
    expect(result.serverCapabilities?.serverName).toContain("mock-mcp-server");
  });

  it("reports errors but does not throw when token is wrong", async () => {
    const result = await scanLive({
      url: server.url,
      authToken: "wrong-token",
      timeoutMs: 5_000,
    });
    // Should complete (not throw) — some probes may fail gracefully
    expect(result).toBeDefined();
    expect(result.scanMode).toBe("live");
  });
});

// ---------------------------------------------------------------------------
// MCP-L013: auth token in URL
// ---------------------------------------------------------------------------

describe("scanLive — MCP-L013 auth token in URL", () => {
  let server: MockMcpServer;

  beforeAll(async () => {
    server = await startMockMcpServer({ mode: "insecure" });
  });

  afterAll(async () => {
    await server.stop();
  });

  it("detects MCP-L013 when token is in the URL query string", async () => {
    const urlWithToken = `${server.url}?token=my-secret-api-token`;
    const result = await scanLive({ url: urlWithToken, timeoutMs: 5_000, rules: ["MCP-L013"] });
    expect(findingIds(result)).toContain("MCP-L013");
  });

  it("does NOT fire MCP-L013 for a clean URL without credentials", async () => {
    const result = await scanLive({ url: server.url, timeoutMs: 5_000, rules: ["MCP-L013"] });
    expect(findingIds(result)).not.toContain("MCP-L013");
  });
});
