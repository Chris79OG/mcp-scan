/**
 * CLI integration tests — spawn the compiled dist/cli.js and verify
 * end-to-end behaviour including option parsing.
 *
 * Regression: Commander parent/subcommand option shadowing (SYNA-129).
 * When both the root program and the `scan` subcommand define `--output`,
 * Commander parses the user value at the parent level, leaving the
 * subcommand with its default. Fix: subcommand action calls optsWithGlobals().
 */

import { spawnSync } from "child_process";
import * as path from "path";
import * as fs from "fs";

const CLI = path.resolve(__dirname, "../../dist/cli.js");
const FIXTURES = path.resolve(__dirname, "../../tests/fixtures");

/** Run the CLI synchronously and return stdout + stderr + exit code. */
function runCli(args: string[]): { stdout: string; stderr: string; status: number } {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf-8",
    timeout: 30_000,
  });
  return {
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    status: result.status ?? 1,
  };
}

describe("CLI — --output option routing (regression: optsWithGlobals)", () => {
  it("scan --output text produces human-readable text, not SARIF JSON", () => {
    const { stdout } = runCli(["scan", FIXTURES, "--output", "text", "--quiet"]);
    // Text output starts with "mcp-scan —", not a JSON object
    expect(stdout.trimStart()).toMatch(/^.{0,10}mcp-scan/);
    expect(stdout).not.toContain('"$schema"');
    expect(stdout).not.toContain('"version": "2.1.0"');
  });

  it("scan --output json produces JSON array output, not SARIF", () => {
    const { stdout } = runCli(["scan", FIXTURES, "--output", "json", "--quiet"]);
    const parsed = JSON.parse(stdout) as unknown;
    // JSON output is the raw ScanResult object (has 'findings' key, not 'runs')
    expect(parsed).toHaveProperty("findings");
    expect(parsed).not.toHaveProperty("runs");
  });

  it("scan --output sarif (default) produces SARIF 2.1.0", () => {
    const { stdout } = runCli(["scan", FIXTURES, "--output", "sarif", "--quiet"]);
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    expect(parsed.version).toBe("2.1.0");
    expect(parsed).toHaveProperty("runs");
  });

  it("scan with no --output flag defaults to SARIF", () => {
    const { stdout } = runCli(["scan", FIXTURES, "--quiet"]);
    const parsed = JSON.parse(stdout) as Record<string, unknown>;
    expect(parsed.version).toBe("2.1.0");
  });

  it("text output shows [ERROR] and [WARNING] labels", () => {
    const { stdout } = runCli(["scan", FIXTURES, "--output", "text", "--quiet"]);
    expect(stdout).toContain("[ERROR]");
    expect(stdout).toContain("[WARNING]");
  });

  it("exits with code 1 when error-severity findings present", () => {
    const { status } = runCli(["scan", FIXTURES, "--output", "text", "--quiet"]);
    expect(status).toBe(1);
  });

  it("text output does NOT include 'Run with --output text' hint when already using text", () => {
    const { stderr } = runCli(["scan", FIXTURES, "--output", "text"]);
    expect(stderr).not.toContain("Run with --output text");
  });

  it("SARIF output includes 'Run with --output text' hint in stderr", () => {
    const { stderr } = runCli(["scan", FIXTURES, "--output", "sarif"]);
    expect(stderr).toContain("Run with --output text");
  });

  it("reports version with -v flag", () => {
    const { stdout } = runCli(["-v"]);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("exits with code 0 when target has no findings", () => {
    // Create a temp clean directory with no MCP server code
    const tmpDir = path.join(require("os").tmpdir(), "mcp-scan-clean-test");
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, "clean.ts"), "// nothing suspicious\nconst x = 1;\n");
    try {
      const { status } = runCli(["scan", tmpDir, "--quiet"]);
      expect(status).toBe(0);
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
