#!/usr/bin/env node
import { Command } from "commander";
import * as path from "path";
import * as fs from "fs";
import { OutputFormat } from "./types";
import { scan } from "./scanner";
import { scanLive } from "./live-scanner";
import { toSarif } from "./formatters/sarif";
import { toText } from "./formatters/text";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const pkg = require("../package.json") as { version: string; description: string };

/** Write a progress message to stderr (never pollutes stdout). */
function progress(step: number, total: number, message: string): void {
  process.stderr.write(`[${step}/${total}] ${message}\n`);
}

const program = new Command();

program
  .name("mcp-scan")
  .description(pkg.description)
  .version(pkg.version, "-v, --version", "Print version number")
  .helpOption("-h, --help", "Show usage information")
  .addHelpText(
    "after",
    `
Examples:
  Scan a local MCP server project:
    $ mcp-scan --input ./my-mcp-server

  Scan a live MCP server endpoint:
    $ mcp-scan --input http://localhost:3000

  Scan with authentication token:
    $ mcp-scan --input https://api.example.com/mcp --auth-token my-api-key

  Scan and output as JSON:
    $ mcp-scan --input ./my-mcp-server --output json

  Scan and write SARIF to a file:
    $ mcp-scan --input ./my-mcp-server --output sarif > results.sarif.json

  Run only specific rules:
    $ mcp-scan --input ./my-mcp-server --rules MCP-001,MCP-006

  Suppress progress output:
    $ mcp-scan --input ./my-mcp-server --quiet

Exit codes:
  0  No error-severity findings.
  1  One or more error-severity findings, or a fatal scan error.
`,
  );

program
  .requiredOption(
    "--input <path|url>",
    "Path to local MCP server directory, or HTTP/HTTPS URL of a live MCP server",
  )
  .option(
    "--output <format>",
    "Output format: sarif | json | text",
    "sarif",
  )
  .option(
    "--auth-token <token>",
    "Bearer token for authenticating against a live MCP server",
  )
  .option(
    "--rules <ids>",
    "Comma-separated list of rule IDs to apply (e.g. MCP-001,MCP-006). Defaults to all rules.",
  )
  .option(
    "--timeout <ms>",
    "Per-request timeout in milliseconds for live scans (default: 10000)",
    "10000",
  )
  .option(
    "-q, --quiet",
    "Suppress progress output to stderr",
  )
  .action(async (opts: {
    input: string;
    output: string;
    authToken?: string;
    rules?: string;
    timeout: string;
    quiet?: boolean;
  }) => {
    const outputFormat = opts.output as OutputFormat;
    const validFormats: OutputFormat[] = ["sarif", "json", "text"];

    if (!validFormats.includes(outputFormat)) {
      process.stderr.write(
        `Error: --output must be one of: ${validFormats.join(", ")}\n`,
      );
      process.exitCode = 1;
      return;
    }

    const timeoutMs = parseInt(opts.timeout, 10);
    if (isNaN(timeoutMs) || timeoutMs < 100) {
      process.stderr.write("Error: --timeout must be a number >= 100\n");
      process.exitCode = 1;
      return;
    }

    const ruleFilter = opts.rules
      ? opts.rules.split(",").map((r) => r.trim()).filter(Boolean)
      : undefined;

    const log = opts.quiet ? () => {} : progress;
    const input = opts.input;
    const isUrl =
      input.startsWith("http://") || input.startsWith("https://");

    try {
      let result;

      if (isUrl) {
        // Live endpoint scan
        log(1, 4, `Connecting to MCP server at ${input}…`);
        log(2, 4, "Enumerating tools and resources…");

        result = await scanLive({
          url: input,
          authToken: opts.authToken,
          timeoutMs,
          rules: ruleFilter,
        });

        log(3, 4, `Found ${result.findings.length} finding(s) across ${result.filesScanned} probe(s).`);
        log(4, 4, result.trustScore
          ? `Trust score: ${result.trustScore.overall}/100 (Grade ${result.trustScore.grade})`
          : "Trust score unavailable.");
      } else {
        // Static file scan
        const resolved = path.resolve(input);
        if (!fs.existsSync(resolved)) {
          process.stderr.write(`Error: Input path does not exist: ${resolved}\n`);
          process.exitCode = 1;
          return;
        }

        log(1, 3, `Scanning ${resolved}…`);

        result = await scan({ input, rules: ruleFilter });

        log(2, 3, `Scanned ${result.filesScanned} file(s).`);
        log(3, 3, `Found ${result.findings.length} finding(s).`);

        result = { ...result, scanMode: "static" as const };
      }

      switch (outputFormat) {
        case "sarif":
          process.stdout.write(JSON.stringify(toSarif(result), null, 2) + "\n");
          break;
        case "json":
          process.stdout.write(JSON.stringify(result, null, 2) + "\n");
          break;
        case "text":
          process.stdout.write(toText(result) + "\n");
          break;
      }

      if (result.summary.errors > 0) {
        process.exitCode = 1;
      }
    } catch (err) {
      process.stderr.write(
        `Error: ${err instanceof Error ? err.message : String(err)}\n`,
      );
      process.exitCode = 1;
    }
  });

program.parse(process.argv);
