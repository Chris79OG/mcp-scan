#!/usr/bin/env node
import { Command } from "commander";
import * as path from "path";
import * as fs from "fs";
import { OutputFormat } from "./types";
import { scan } from "./scanner";
import { scanLive } from "./live-scanner";
import { toSarif } from "./formatters/sarif";
import { toText } from "./formatters/text";
import { RULES } from "./rules";
import {
  getCurrentSubscription,
  verifyApiKey,
  getApiKey,
  getCheckoutUrl,
  TIER_LABELS,
  TIER_FEATURES,
} from "./billing";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const pkg = require("../package.json") as { version: string; description: string };

// ---------------------------------------------------------------------------
// Progress & spinner helpers
// ---------------------------------------------------------------------------

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/**
 * Start a terminal spinner on stderr. Returns a stop function.
 * Safe to call when stderr is not a TTY (no-ops in that case).
 */
function startSpinner(message: string): () => void {
  if (!process.stderr.isTTY) return () => {};
  let frameIdx = 0;
  process.stderr.write(`  ${SPINNER_FRAMES[0]} ${message}`);
  const timer = setInterval(() => {
    process.stderr.write(`\r  ${SPINNER_FRAMES[frameIdx % SPINNER_FRAMES.length]} ${message}`);
    frameIdx++;
  }, 80);
  return () => {
    clearInterval(timer);
    process.stderr.write("\r\x1b[K"); // clear the spinner line
  };
}

/** Write a progress line to stderr. */
function progress(step: number, total: number, message: string, quiet: boolean): void {
  if (!quiet) {
    process.stderr.write(`[${step}/${total}] ${message}\n`);
  }
}

/** Write a verbose-only message to stderr. */
function verbose(message: string, isVerbose: boolean): void {
  if (isVerbose) {
    process.stderr.write(`  » ${message}\n`);
  }
}

/** Format a user-friendly error with an optional suggestion. */
function fatalError(message: string, suggestion?: string): void {
  process.stderr.write(`\n  ✗ Error: ${message}\n`);
  if (suggestion) {
    process.stderr.write(`    Hint: ${suggestion}\n`);
  }
  process.stderr.write("\n");
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

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
    $ mcp-scan scan ./my-mcp-server

  Scan a live MCP server endpoint:
    $ mcp-scan scan http://localhost:3000

  Scan with authentication token:
    $ mcp-scan scan https://api.example.com/mcp --auth-token my-api-key

  Scan and output as JSON:
    $ mcp-scan scan ./my-mcp-server --output json

  Scan and write SARIF to a file (e.g. for GitHub Code Scanning):
    $ mcp-scan scan ./my-mcp-server --output sarif > results.sarif.json

  Run only specific rules:
    $ mcp-scan scan ./my-mcp-server --rules MCP-001,MCP-006

  Show detailed scan steps:
    $ mcp-scan scan ./my-mcp-server --verbose

  Suppress all progress output (CI-friendly):
    $ mcp-scan scan ./my-mcp-server --quiet

Exit codes:
  0  No error-severity findings.
  1  One or more error-severity findings, or a fatal scan error.

Available static rules (${RULES.length} total):
${RULES.map((r) => `  ${r.id.padEnd(9)} ${r.defaultSeverity.padEnd(8)} ${r.name}`).join("\n")}
`,
  );

// ---------------------------------------------------------------------------
// Shared scan options type and core action
// ---------------------------------------------------------------------------

interface ScanOpts {
  output: string;
  authToken?: string;
  rules?: string;
  timeout: string;
  quiet?: boolean;
  verbose?: boolean;
}

/**
 * Core scan action shared by both the root `--input` interface and the
 * `scan <target>` subcommand.
 */
async function runScanAction(input: string, opts: ScanOpts): Promise<void> {
  const outputFormat = opts.output as OutputFormat;
  const validFormats: OutputFormat[] = ["sarif", "json", "text"];
  const quiet = opts.quiet ?? false;
  const isVerbose = (!quiet) && (opts.verbose ?? false);

  if (!validFormats.includes(outputFormat)) {
    fatalError(
      `--output must be one of: ${validFormats.join(", ")} (got: "${opts.output}")`,
      `Try: mcp-scan scan ${input} --output text`,
    );
    process.exitCode = 1;
    return;
  }

  const timeoutMs = parseInt(opts.timeout, 10);
  if (isNaN(timeoutMs) || timeoutMs < 100) {
    fatalError(
      `--timeout must be a number >= 100 (got: "${opts.timeout}")`,
      "Example: --timeout 30000 for a 30-second timeout",
    );
    process.exitCode = 1;
    return;
  }

  const ruleFilter = opts.rules
    ? opts.rules.split(",").map((r) => r.trim()).filter(Boolean)
    : undefined;

  if (ruleFilter) {
    // Warn about unknown rule IDs (but don't fail — live rules aren't in RULES array)
    const knownStaticIds = new Set(RULES.map((r) => r.id));
    const unknownIds = ruleFilter.filter(
      (id) => !knownStaticIds.has(id) && !id.startsWith("MCP-L"),
    );
    if (unknownIds.length > 0 && !quiet) {
      process.stderr.write(
        `  ⚠  Unknown rule ID(s): ${unknownIds.join(", ")} — these will be skipped.\n`,
      );
    }
    verbose(`Active rule filter: ${ruleFilter.join(", ")}`, isVerbose);
  } else {
    verbose(`All rules active (${RULES.length} static rules + live rules for endpoint scans)`, isVerbose);
  }

  const isUrl = input.startsWith("http://") || input.startsWith("https://");

  try {
    let result;

    if (isUrl) {
      // -----------------------------------------------------------------------
      // Live endpoint scan
      // -----------------------------------------------------------------------
      if (!quiet) {
        process.stderr.write(`\nmcp-scan  live endpoint\n`);
        process.stderr.write(`${"─".repeat(50)}\n`);
      }
      progress(1, 4, `Connecting to ${input}…`, quiet);
      verbose(`Timeout: ${timeoutMs}ms`, isVerbose);

      const stopSpinner = startSpinner("Probing MCP server…");

      result = await scanLive({
        url: input,
        authToken: opts.authToken,
        timeoutMs,
        rules: ruleFilter,
      });

      stopSpinner();

      progress(2, 4, "Analyzing tool definitions and schemas…", quiet);
      verbose(
        `Server: ${result.serverCapabilities?.serverName ?? "unknown"} ` +
        `v${result.serverCapabilities?.serverVersion ?? "?"}`,
        isVerbose,
      );
      progress(3, 4, `Found ${result.findings.length} finding(s) across ${result.filesScanned} probe(s).`, quiet);
      progress(
        4,
        4,
        result.trustScore
          ? `Trust score: ${result.trustScore.overall}/100 — Grade ${result.trustScore.grade}`
          : "Trust score: unavailable",
        quiet,
      );

      if (!quiet && result.findings.length > 0) {
        const errors = result.findings.filter((f) => f.severity === "error").length;
        const warnings = result.findings.filter((f) => f.severity === "warning").length;
        process.stderr.write(`\n  ${errors} error(s), ${warnings} warning(s) found.\n`);
        if (outputFormat !== "text") {
          process.stderr.write(`  Run with --output text for remediation guidance.\n`);
        }
      }
    } else {
      // -----------------------------------------------------------------------
      // Static file scan
      // -----------------------------------------------------------------------
      const resolved = path.resolve(input);
      if (!fs.existsSync(resolved)) {
        fatalError(
          `Input path does not exist: ${resolved}`,
          `Check the path spelling, or use an HTTP(S) URL for live endpoint scanning.`,
        );
        process.exitCode = 1;
        return;
      }

      const stat = fs.statSync(resolved);
      const targetLabel = stat.isDirectory() ? "directory" : "file";

      if (!quiet) {
        process.stderr.write(`\nmcp-scan  static scan\n`);
        process.stderr.write(`${"─".repeat(50)}\n`);
      }
      progress(1, 3, `Scanning ${targetLabel}: ${resolved}`, quiet);
      verbose(`Rules: ${ruleFilter ? ruleFilter.join(", ") : "all"}`, isVerbose);

      result = await scan({ input, rules: ruleFilter });
      result = { ...result, scanMode: "static" as const };

      progress(2, 3, `Scanned ${result.filesScanned} file(s).`, quiet);
      progress(3, 3, `Found ${result.findings.length} finding(s).`, quiet);

      if (!quiet && result.findings.length > 0) {
        const errors = result.findings.filter((f) => f.severity === "error").length;
        const warnings = result.findings.filter((f) => f.severity === "warning").length;
        process.stderr.write(`\n  ${errors} error(s), ${warnings} warning(s) found.\n`);
        if (outputFormat !== "text") {
          process.stderr.write(`  Run with --output text for remediation guidance.\n`);
        }
      } else if (!quiet) {
        process.stderr.write("\n  No findings — looking clean.\n");
      }
    }

    if (!quiet) process.stderr.write("\n");

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
    const msg = err instanceof Error ? err.message : String(err);
    const isConnRefused = msg.includes("ECONNREFUSED") || msg.includes("ENOTFOUND");
    fatalError(
      msg,
      isConnRefused
        ? `Check that the MCP server is running and reachable at ${input}`
        : "Run with --verbose for more detail, or check the target is accessible.",
    );
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Root program — legacy --input interface (kept for backwards compat)
// ---------------------------------------------------------------------------

program
  .option(
    "--input <path|url>",
    "Path to local MCP server directory, or HTTP/HTTPS URL of a live MCP server",
  )
  .option(
    "--output <format>",
    "Output format: sarif | json | text  (default: sarif)",
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
    "Suppress all progress output to stderr",
  )
  .option(
    "--verbose",
    "Print detailed step-by-step progress to stderr",
  )
  .action(async (opts: ScanOpts & { input?: string }) => {
    if (!opts.input) {
      fatalError(
        "No target specified.",
        "Use: mcp-scan scan <path|url>  or  mcp-scan --input <path|url>",
      );
      process.exitCode = 1;
      return;
    }
    await runScanAction(opts.input, opts);
  });

// ---------------------------------------------------------------------------
// scan <target> — preferred interface: mcp-scan scan <path|url>
// ---------------------------------------------------------------------------

program
  .command("scan <target>")
  .description("Scan an MCP server by path or URL")
  .option(
    "--output <format>",
    "Output format: sarif | json | text  (default: sarif)",
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
    "Suppress all progress output to stderr",
  )
  .option(
    "--verbose",
    "Print detailed step-by-step progress to stderr",
  )
  .action(async (target: string, _opts: ScanOpts, cmd: InstanceType<typeof Command>) => {
    await runScanAction(target, cmd.optsWithGlobals() as ScanOpts);
  });

// ---------------------------------------------------------------------------
// subscribe command — open Stripe checkout
// ---------------------------------------------------------------------------

program
  .command("subscribe")
  .description("Upgrade to Pro or Enterprise and get your API key")
  .option("--tier <tier>", "Subscription tier: pro | enterprise", "pro")
  .option("--email <email>", "Your email address (pre-fills checkout)")
  .action(async (opts: { tier: string; email?: string }) => {
    const tier = opts.tier as "pro" | "enterprise";
    if (!["pro", "enterprise"].includes(tier)) {
      process.stderr.write(`Error: --tier must be 'pro' or 'enterprise'\n`);
      process.exitCode = 1;
      return;
    }

    const price = tier === "pro" ? "$19/mo" : "$99/mo";
    const features = TIER_FEATURES[tier];

    process.stderr.write(`\nmcp-scan ${TIER_LABELS[tier]}\n`);
    process.stderr.write(`${"─".repeat(50)}\n`);
    process.stderr.write(`\nFeatures included:\n`);
    features.forEach((f) => process.stderr.write(`  ✓ ${f}\n`));
    process.stderr.write(`\nPrice: ${price}\n\n`);

    // Try to get a checkout URL from the Foundry billing service
    const foundryUrl = process.env.FOUNDRY_API_URL || "http://localhost:8800";
    const subscribeEndpoint = `${foundryUrl}/v1/billing/subscribe`;

    try {
      const body: Record<string, string> = { tier };
      if (opts.email) body.email = opts.email;

      const res = await fetch(subscribeEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(5000),
      });

      if (res.ok) {
        const data = (await res.json()) as { checkout_url?: string; error?: string };
        if (data.checkout_url) {
          process.stderr.write(`Open this URL to complete your subscription:\n\n`);
          process.stdout.write(`${data.checkout_url}\n`);
          process.stderr.write(`\nAfter payment, set your API key:\n`);
          process.stderr.write(`  export MCP_SCAN_API_KEY=<your-key>\n\n`);
          return;
        }
      }
    } catch {
      // Billing service unreachable — show manual instructions
    }

    // Fallback: direct URL
    const url = getCheckoutUrl(tier, opts.email);
    process.stderr.write(`Open this URL to complete your subscription:\n\n`);
    process.stdout.write(`${url}\n`);
    process.stderr.write(`\nAfter payment, set your API key:\n`);
    process.stderr.write(`  export MCP_SCAN_API_KEY=<your-key>\n\n`);
  });

// ---------------------------------------------------------------------------
// billing command — show current subscription status
// ---------------------------------------------------------------------------

program
  .command("billing")
  .description("Show current subscription status and API key info")
  .option("--verify <key>", "Verify a specific API key")
  .action(async (opts: { verify?: string }) => {
    process.stderr.write(`\nmcp-scan Billing\n`);
    process.stderr.write(`${"─".repeat(50)}\n`);

    if (opts.verify) {
      const info = await verifyApiKey(opts.verify);
      process.stderr.write(`\nAPI key: ${opts.verify.slice(0, 12)}...\n`);
      process.stderr.write(`  Tier   : ${TIER_LABELS[info.tier]}\n`);
      process.stderr.write(`  Valid  : ${info.valid ? "yes" : "no"}\n`);
      process.stderr.write(`  Active : ${info.active ? "yes" : "no"}\n`);
      if (info.email) process.stderr.write(`  Email  : ${info.email}\n`);
      return;
    }

    const apiKey = getApiKey();
    if (!apiKey) {
      process.stderr.write(`\nNo API key found (MCP_SCAN_API_KEY not set).\n`);
      process.stderr.write(`Current plan: ${TIER_LABELS.free}\n`);
      process.stderr.write(`\nUpgrade to Pro for $19/mo:\n`);
      process.stderr.write(`  mcp-scan subscribe --tier pro\n\n`);
      return;
    }

    const sub = await getCurrentSubscription();
    process.stderr.write(`\nAPI key: ${apiKey.slice(0, 12)}...\n`);
    process.stderr.write(`  Tier   : ${TIER_LABELS[sub.tier]}\n`);
    process.stderr.write(`  Valid  : ${sub.valid ? "yes" : "no"}\n`);
    process.stderr.write(`  Active : ${sub.active ? "yes" : "no"}\n`);
    if (sub.email) process.stderr.write(`  Email  : ${sub.email}\n`);

    const features = TIER_FEATURES[sub.tier];
    process.stderr.write(`\nIncluded features:\n`);
    features.forEach((f) => process.stderr.write(`  ✓ ${f}\n`));
    process.stderr.write("\n");
  });

program.parse(process.argv);
