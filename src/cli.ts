#!/usr/bin/env node
import { Command } from "commander";
import * as path from "path";
import * as fs from "fs";
import { OutputFormat } from "./types";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const pkg = require("../package.json") as { version: string; description: string };

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

  Scan and output as JSON:
    $ mcp-scan --input ./my-mcp-server --output json

  Scan and write SARIF to a file:
    $ mcp-scan --input ./my-mcp-server --output sarif > results.sarif.json
`,
  );

program
  .requiredOption(
    "--input <path|url>",
    "Path to local MCP server directory, or URL of a remote MCP server",
  )
  .option(
    "--output <format>",
    "Output format: sarif | json | text",
    "sarif",
  )
  .action((opts: { input: string; output: string }) => {
    const outputFormat = opts.output as OutputFormat;
    const validFormats: OutputFormat[] = ["sarif", "json", "text"];

    if (!validFormats.includes(outputFormat)) {
      console.error(
        `Error: --output must be one of: ${validFormats.join(", ")}`,
      );
      process.exitCode = 1;
      return;
    }

    const input = opts.input;

    // Validate local path if not a URL
    if (!input.startsWith("http://") && !input.startsWith("https://")) {
      const resolved = path.resolve(input);
      if (!fs.existsSync(resolved)) {
        console.error(`Error: Input path does not exist: ${resolved}`);
        process.exitCode = 1;
        return;
      }
    }

    // Placeholder: scanning engine will be wired in SYNA-33
    console.error(
      `[mcp-scan] Scanning ${input} (output: ${outputFormat}) — scanner engine not yet implemented`,
    );
    process.exitCode = 0;
  });

program.parse(process.argv);
