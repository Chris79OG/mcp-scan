/**
 * mcp-scan HTTP service
 *
 * Exposes three endpoints:
 *   GET  /health   — liveness probe (returns {"status":"ok"})
 *   GET  /metrics  — Prometheus-compatible plaintext metrics
 *   POST /scan     — run a scan; body: {"input":"<path>","rules":[...]}
 *
 * Start: node dist/server.js [--port 3000]
 */

import * as http from "http";
import * as url from "url";
import { scan, ScanOptions } from "./scanner";

// ── Metrics store ────────────────────────────────────────────────────────────
let scanCount = 0;
let scanErrors = 0;
let totalLatencyMs = 0;
const startedAt = Date.now();

// ── Helpers ──────────────────────────────────────────────────────────────────

function send(res: http.ServerResponse, status: number, body: string, ct = "application/json"): void {
  res.writeHead(status, { "Content-Type": ct, "Content-Length": Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

function metricsText(): string {
  const uptimeSeconds = ((Date.now() - startedAt) / 1000).toFixed(1);
  const avgLatency = scanCount > 0 ? (totalLatencyMs / scanCount).toFixed(1) : "0";
  return [
    "# HELP mcp_scan_total Total number of scans executed",
    "# TYPE mcp_scan_total counter",
    `mcp_scan_total ${scanCount}`,
    "",
    "# HELP mcp_scan_errors_total Total number of scans that returned errors",
    "# TYPE mcp_scan_errors_total counter",
    `mcp_scan_errors_total ${scanErrors}`,
    "",
    "# HELP mcp_scan_avg_latency_ms Average scan latency in milliseconds",
    "# TYPE mcp_scan_avg_latency_ms gauge",
    `mcp_scan_avg_latency_ms ${avgLatency}`,
    "",
    "# HELP mcp_scan_uptime_seconds Server uptime in seconds",
    "# TYPE mcp_scan_uptime_seconds gauge",
    `mcp_scan_uptime_seconds ${uptimeSeconds}`,
    "",
  ].join("\n");
}

// ── Request handler ──────────────────────────────────────────────────────────

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const parsed = url.parse(req.url ?? "/");
  const pathname = parsed.pathname ?? "/";

  // GET /health
  if (req.method === "GET" && pathname === "/health") {
    send(res, 200, JSON.stringify({ status: "ok", uptime: Date.now() - startedAt }));
    return;
  }

  // GET /metrics
  if (req.method === "GET" && pathname === "/metrics") {
    send(res, 200, metricsText(), "text/plain; version=0.0.4; charset=utf-8");
    return;
  }

  // POST /scan
  if (req.method === "POST" && pathname === "/scan") {
    let body: { input?: string; rules?: string[] };
    try {
      body = JSON.parse(await readBody(req)) as { input?: string; rules?: string[] };
    } catch {
      send(res, 400, JSON.stringify({ error: "Invalid JSON body" }));
      return;
    }

    if (!body.input || typeof body.input !== "string") {
      send(res, 400, JSON.stringify({ error: '"input" (string) is required' }));
      return;
    }

    const opts: ScanOptions = { input: body.input };
    if (Array.isArray(body.rules)) opts.rules = body.rules;

    const t0 = Date.now();
    try {
      const result = await scan(opts);
      const latency = Date.now() - t0;
      scanCount++;
      totalLatencyMs += latency;
      if (result.summary.errors > 0) scanErrors++;
      send(res, 200, JSON.stringify({ ...result, latencyMs: latency }));
    } catch (err) {
      scanCount++;
      scanErrors++;
      const msg = err instanceof Error ? err.message : String(err);
      send(res, 500, JSON.stringify({ error: msg }));
    }
    return;
  }

  send(res, 404, JSON.stringify({ error: "Not found" }));
}

// ── Bootstrap ────────────────────────────────────────────────────────────────

const port = parseInt(process.env.PORT ?? "3000", 10);

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch((err) => {
    console.error("[mcp-scan server] unhandled error:", err);
    send(res, 500, JSON.stringify({ error: "Internal server error" }));
  });
});

server.listen(port, () => {
  console.log(JSON.stringify({ event: "server_started", port, pid: process.pid }));
});

server.on("error", (err) => {
  console.error(JSON.stringify({ event: "server_error", message: (err as NodeJS.ErrnoException).message }));
  process.exit(1);
});

process.on("SIGTERM", () => {
  console.log(JSON.stringify({ event: "shutdown", reason: "SIGTERM" }));
  server.close(() => process.exit(0));
});
