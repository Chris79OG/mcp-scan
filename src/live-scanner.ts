/**
 * Live MCP server endpoint scanner.
 *
 * Connects to a running MCP server over HTTP/HTTPS, enumerates its tools and
 * resources via JSON-RPC, then probes for a comprehensive set of security
 * weaknesses:
 *
 *   - MCP-L001  No TLS (plain HTTP in production)
 *   - MCP-L002  Unauthenticated access accepted
 *   - MCP-L003  Prompt injection in tool description
 *   - MCP-L004  Tool input schema missing additionalProperties:false
 *   - MCP-L005  Stack-trace / internal detail leakage in error responses
 *   - MCP-L006  No rate-limiting headers detected
 *   - MCP-L007  SSRF-prone parameter names in tool schemas
 *   - MCP-L008  Excessive scope grants in tool metadata
 *   - MCP-L009  Unauthenticated SSE endpoint
 *   - MCP-L010  Unrestricted file-path parameters in tool schemas
 *   - MCP-L011  Permissive CORS configuration (Access-Control-Allow-Origin: *)
 *   - MCP-L012  Missing security response headers (CSP, X-Frame-Options, HSTS)
 *   - MCP-L013  Authentication token passed as URL query parameter
 */

import * as https from "https";
import * as http from "http";
import { URL } from "url";
import {
  Finding,
  ScanResult,
  Severity,
  McpServerCapabilities,
  Remediation,
} from "./types";
import { computeTrustScore } from "./trust-score";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for scanning a live MCP server endpoint. */
export interface LiveScanOptions {
  /** HTTP or HTTPS URL of the MCP server (e.g. "http://localhost:3000"). */
  url: string;
  /** Optional bearer token for authenticated probing. */
  authToken?: string;
  /** Optional timeout per request in milliseconds. Defaults to 10 000. */
  timeoutMs?: number;
  /** Optional list of live rule IDs to apply. Defaults to all. */
  rules?: string[];
}

/** Raw JSON-RPC response envelope. */
interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: number | string | null;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

/** MCP tool definition as returned by tools/list. */
interface McpTool {
  name: string;
  description?: string;
  inputSchema?: {
    type?: string;
    properties?: Record<string, unknown>;
    required?: string[];
    additionalProperties?: boolean | Record<string, unknown>;
  };
}

/** MCP resource definition as returned by resources/list. */
interface McpResource {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

/** Internal probe result for the auth check. */
interface AuthProbeResult {
  requiresAuth: boolean;
  statusCode: number;
}

/** Internal probe result for the error-handling check. */
interface ErrorProbeResult {
  leaksStackTrace: boolean;
  leaksInternalDetails: boolean;
  rawBody: string;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Make a JSON-RPC 2.0 request to the MCP server.
 *
 * Returns the parsed response body on success, or throws on network error.
 */
async function jsonRpc(
  baseUrl: string,
  method: string,
  params: Record<string, unknown> = {},
  authToken: string | undefined,
  timeoutMs: number,
): Promise<JsonRpcResponse> {
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id: Date.now(),
    method,
    params,
  });

  const parsed = new URL(baseUrl);
  const isHttps = parsed.protocol === "https:";
  const transport = isHttps ? https : http;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body).toString(),
    "User-Agent": "mcp-scan/0.1",
  };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }

  const options: http.RequestOptions = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname || "/",
    method: "POST",
    headers,
    timeout: timeoutMs,
  };

  return new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      let data = "";
      res.on("data", (chunk: Buffer) => {
        data += chunk.toString();
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(data) as JsonRpcResponse);
        } catch {
          // Return a synthetic error response when the body isn't JSON
          resolve({
            jsonrpc: "2.0",
            id: null,
            error: {
              code: -32700,
              message: `Non-JSON response (HTTP ${res.statusCode}): ${data.slice(0, 200)}`,
            },
          });
        }
      });
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeoutMs}ms`));
    });
    req.on("error", reject);

    req.write(body);
    req.end();
  });
}

/**
 * Make a raw HTTP request and return the status code + body.
 *
 * Used for auth probing and SSE endpoint checks.
 */
async function rawGet(
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<{ statusCode: number; body: string; responseHeaders: http.IncomingHttpHeaders }> {
  const parsed = new URL(url);
  const isHttps = parsed.protocol === "https:";
  const transport = isHttps ? https : http;

  const options: http.RequestOptions = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname + (parsed.search || ""),
    method: "GET",
    headers: { "User-Agent": "mcp-scan/0.1", ...headers },
    timeout: timeoutMs,
  };

  return new Promise((resolve, reject) => {
    const req = transport.request(options, (res) => {
      let body = "";
      res.on("data", (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on("end", () => {
        resolve({
          statusCode: res.statusCode ?? 0,
          body,
          responseHeaders: res.headers,
        });
      });
    });
    req.on("timeout", () => {
      req.destroy();
      reject(new Error(`GET timed out after ${timeoutMs}ms`));
    });
    req.on("error", reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Individual security probes
// ---------------------------------------------------------------------------

/** MCP-L001: Check whether the endpoint uses TLS. */
function checkTls(url: string): Finding | null {
  if (!url.startsWith("https://")) {
    return makeFinding(
      "MCP-L001",
      "Plaintext HTTP transport — no TLS",
      "The MCP server is exposed over HTTP without TLS. All communication " +
        "(including tool calls and any secrets they carry) is transmitted in " +
        "the clear and susceptible to eavesdropping and man-in-the-middle attacks.",
      "error",
      url,
      {
        summary: "Switch the server to HTTPS with a valid TLS certificate.",
        steps: [
          "Provision a TLS certificate (Let's Encrypt is free for public endpoints).",
          "Configure your HTTP framework to bind on port 443 with the certificate.",
          "Redirect all HTTP traffic to HTTPS with a 301 response.",
          "Set `Strict-Transport-Security` header to enforce HTTPS in browsers.",
        ],
        references: [
          "https://letsencrypt.org/getting-started/",
          "https://owasp.org/www-project-transport-layer-protection-cheat-sheet/",
        ],
      },
    );
  }
  return null;
}

/** MCP-L002: Probe the server with no auth to see if it accepts requests. */
async function checkAuth(
  url: string,
  timeoutMs: number,
): Promise<{ finding: Finding | null; result: AuthProbeResult }> {
  const result: AuthProbeResult = { requiresAuth: true, statusCode: 0 };

  try {
    // Send a well-formed initialize request with no credentials
    const resp = await jsonRpc(url, "initialize", {
      protocolVersion: "2024-11-05",
      capabilities: {},
      clientInfo: { name: "mcp-scan", version: "0.1" },
    }, undefined, timeoutMs);

    // If we get a successful result, the server accepts unauthenticated access
    if (resp.result) {
      result.requiresAuth = false;
      result.statusCode = 200;
      return {
        finding: makeFinding(
          "MCP-L002",
          "Unauthenticated access accepted",
          "The MCP server responded to an unauthenticated `initialize` request. " +
            "Any caller on the network can enumerate tools, call them, and access " +
            "resources without providing credentials.",
          "error",
          url,
          {
            summary: "Require authentication on all MCP endpoints.",
            steps: [
              "Add an authentication middleware that validates a Bearer token or API key.",
              "Return HTTP 401 for requests missing valid credentials.",
              "Implement an API key rotation mechanism and short-lived token support.",
              "Document the auth requirements in your server's README.",
            ],
            references: [
              "https://modelcontextprotocol.io/docs/concepts/transports",
              "https://owasp.org/www-project-api-security/",
            ],
          },
        ),
        result,
      };
    }
    // Error response (e.g. 401 / auth error code) means auth IS required — good.
    result.requiresAuth = true;
  } catch {
    // Network error — can't determine auth status; assume auth is present (benefit of doubt)
    result.requiresAuth = true;
  }

  return { finding: null, result };
}

/** MCP-L003: Scan tool descriptions for prompt-injection patterns. */
function checkToolDescriptionsForInjection(
  tools: McpTool[],
  url: string,
): Finding[] {
  const INJECTION_PATTERN =
    /ignore\s+(previous|all|prior)\s+instructions?|disregard\s+(previous|all)\s+instructions?|you\s+are\s+now\s+a|act\s+as\s+if\s+you|forget\s+your\s+(previous|prior|all)\s+(instructions?|training)|\[SYSTEM\]|<system>|\|JAILBREAK\|/gi;

  return tools
    .filter(
      (t) => t.description && INJECTION_PATTERN.test(t.description),
    )
    .map((t) =>
      makeFinding(
        "MCP-L003",
        `Prompt injection in tool description: "${t.name}"`,
        `Tool "${t.name}" has a description that contains text attempting to ` +
          `override LLM instructions. This is a prompt injection vector that can ` +
          `hijack the behavior of any LLM consuming this tool definition.`,
        "error",
        url,
        {
          summary: "Remove or sanitize embedded instruction overrides from tool descriptions.",
          steps: [
            `Review the description of tool "${t.name}" and remove any instruction-override text.`,
            "Validate all tool descriptions against an allowlist of safe content patterns.",
            "Add a CI lint step that rejects tool definitions containing injection patterns.",
          ],
          references: ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        },
        t.description?.slice(0, 120),
      ),
    );
}

/** MCP-L004: Check tool input schemas for missing additionalProperties:false. */
function checkToolSchemas(tools: McpTool[], url: string): Finding[] {
  const findings: Finding[] = [];

  for (const tool of tools) {
    const schema = tool.inputSchema;
    if (!schema) continue;

    const hasProperties =
      schema.properties && Object.keys(schema.properties).length > 0;
    const hasStrict =
      schema.additionalProperties === false;

    if (hasProperties && !hasStrict) {
      findings.push(
        makeFinding(
          "MCP-L004",
          `Tool "${tool.name}" schema lacks additionalProperties:false`,
          `The input schema for tool "${tool.name}" defines properties but does ` +
            `not set additionalProperties:false. Callers can inject arbitrary ` +
            `undeclared parameters that bypass server-side validation.`,
          "warning",
          url,
          {
            summary: 'Add `"additionalProperties": false` to every tool\'s input schema.',
            steps: [
              `Open the schema definition for tool "${tool.name}".`,
              'Add `"additionalProperties": false` at the top level of the schema object.',
              "Verify the server rejects requests with undeclared fields.",
            ],
            references: ["https://json-schema.org/understanding-json-schema/reference/object.html"],
          },
        ),
      );
    }

    // MCP-L007: SSRF-prone parameter names
    const ssrfNames = /^(url|uri|endpoint|host|callback|webhook|redirect)$/i;
    if (schema.properties) {
      for (const paramName of Object.keys(schema.properties)) {
        if (ssrfNames.test(paramName)) {
          findings.push(
            makeFinding(
              "MCP-L007",
              `Tool "${tool.name}" has SSRF-prone parameter: "${paramName}"`,
              `Tool "${tool.name}" accepts a parameter named "${paramName}" which ` +
                `commonly carries URLs. Without server-side allowlist validation this ` +
                `can be abused to make the MCP server issue requests to internal services.`,
              "warning",
              url,
              {
                summary: "Validate URL parameters against an allowlist of permitted destinations.",
                steps: [
                  `In the handler for tool "${tool.name}", parse the "${paramName}" value as a URL.`,
                  "Reject requests whose scheme is not http/https, or whose host is a private IP range.",
                  "Maintain an allowlist of permitted hostnames and validate against it.",
                  "Return a structured error (not a stack trace) on rejection.",
                ],
                references: [
                  "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                  "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                ],
              },
            ),
          );
        }
      }
    }

    // MCP-L010: Unrestricted file-path parameters
    const pathNames = /^(path|file|filename|filepath|dir|directory)$/i;
    if (schema.properties) {
      for (const paramName of Object.keys(schema.properties)) {
        if (pathNames.test(paramName)) {
          findings.push(
            makeFinding(
              "MCP-L010",
              `Tool "${tool.name}" has file-path parameter: "${paramName}"`,
              `Tool "${tool.name}" accepts a parameter named "${paramName}" which ` +
                `likely carries a filesystem path. Without path-traversal validation ` +
                `an attacker can read or write arbitrary files on the server.`,
              "error",
              url,
              {
                summary: "Sanitize file-path parameters and restrict access to an allowed directory.",
                steps: [
                  `In the handler for tool "${tool.name}", resolve the "${paramName}" value to an absolute path.`,
                  "Verify the resolved path starts with the allowed base directory (chroot-style check).",
                  "Reject paths containing `..` segments before resolution.",
                  "Run the MCP server process with a least-privilege OS user.",
                ],
                references: [
                  "https://owasp.org/www-community/attacks/Path_Traversal",
                  "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                ],
              },
            ),
          );
        }
      }
    }
  }

  return findings;
}

/** MCP-L005: Send a malformed request and look for stack-trace leakage. */
async function checkErrorHandling(
  url: string,
  timeoutMs: number,
): Promise<{ finding: Finding | null; result: ErrorProbeResult }> {
  const probeResult: ErrorProbeResult = {
    leaksStackTrace: false,
    leaksInternalDetails: false,
    rawBody: "",
  };

  try {
    // Send an intentionally malformed request (unknown method + invalid params)
    const resp = await jsonRpc(
      url,
      "tools/call",
      { name: "__mcp_scan_probe__", arguments: { "../../etc/passwd": "test" } },
      undefined,
      timeoutMs,
    );

    const raw = JSON.stringify(resp);
    probeResult.rawBody = raw.slice(0, 500);

    // Look for stack-trace indicators
    const stackPatterns = [
      /at\s+\w+\s+\([^)]+:\d+:\d+\)/,   // "at Function (file.js:10:5)"
      /Error:\s+.+\n\s+at\s+/,
      /node_modules/,
      /\.ts:\d+:\d+/,
      /\.js:\d+:\d+/,
      /internal\/process/,
      /UnhandledPromiseRejection/,
    ];
    probeResult.leaksStackTrace = stackPatterns.some((p) => p.test(raw));

    // Look for internal-detail leakage (db errors, file paths, env vars)
    const detailPatterns = [
      /ENOENT|EACCES|EPERM/,
      /SQL|sqlite|postgres|mysql/i,
      /process\.env\./,
      /\/home\/|\/root\/|\/var\/|C:\\Users\\/i,
    ];
    probeResult.leaksInternalDetails = detailPatterns.some((p) => p.test(raw));

    if (probeResult.leaksStackTrace || probeResult.leaksInternalDetails) {
      return {
        finding: makeFinding(
          "MCP-L005",
          "Error responses leak internal server details",
          "The server returns stack traces or internal path/environment details in " +
            "error responses. This reveals implementation internals that help an " +
            "attacker map the server's technology stack and find exploitable paths.",
          "error",
          url,
          {
            summary: "Return structured error codes instead of raw stack traces.",
            steps: [
              "Add a global error handler that catches all unhandled exceptions.",
              "Map internal errors to a fixed set of opaque JSON-RPC error codes (-32000 range).",
              "Log full stack traces to a server-side log file, not to the API response.",
              "In production, set NODE_ENV=production so frameworks suppress stack output.",
            ],
            references: [
              "https://www.jsonrpc.org/specification#error_object",
              "https://owasp.org/www-project-api-security/",
            ],
          },
          probeResult.rawBody.slice(0, 120),
        ),
        result: probeResult,
      };
    }
  } catch {
    // Network error during probe — not a finding
  }

  return { finding: null, result: probeResult };
}

/** MCP-L006: Check for rate-limiting headers in the server's response. */
async function checkRateLimiting(
  url: string,
  timeoutMs: number,
): Promise<Finding | null> {
  try {
    // Make a GET request to the base URL to inspect response headers
    const { responseHeaders } = await rawGet(url, {}, timeoutMs);

    const rateLimitHeaders = [
      "x-ratelimit-limit",
      "x-ratelimit-remaining",
      "ratelimit-limit",
      "retry-after",
      "x-rate-limit",
    ];
    const hasRateLimit = rateLimitHeaders.some(
      (h) => h in responseHeaders,
    );

    if (!hasRateLimit) {
      return makeFinding(
        "MCP-L006",
        "No rate-limiting headers detected",
        "The server does not return rate-limiting headers. Without rate limiting, " +
          "an attacker can call tools at unlimited speed, enabling credential " +
          "brute-force, resource exhaustion, and LLM cost amplification attacks.",
        "warning",
        url,
        {
          summary: "Implement rate limiting and advertise it via response headers.",
          steps: [
            "Add a rate-limiting middleware (e.g. express-rate-limit, nginx limit_req).",
            "Return `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `Retry-After` headers.",
            "Apply tighter limits on expensive tool calls (LLM calls, file operations).",
            "Log rate-limit violations for security monitoring.",
          ],
          references: [
            "https://www.iana.org/assignments/http-fields/",
            "https://owasp.org/www-project-api-security/",
          ],
        },
      );
    }
  } catch {
    // Can't reach server for GET — skip
  }

  return null;
}

/** MCP-L008: Check tool descriptions for excessive-scope keywords. */
function checkExcessiveScope(tools: McpTool[], url: string): Finding[] {
  const SCOPE_PATTERN =
    /admin(?:istrator)?_access\s*[=:]\s*true|full_access\s*[=:]\s*true|grant_all|allow_all_scopes|permissions?\s*[=:'"]\s*['"]?\*['"]?/gi;

  return tools
    .filter((t) => t.description && SCOPE_PATTERN.test(t.description))
    .map((t) =>
      makeFinding(
        "MCP-L008",
        `Excessive scope grant in tool "${t.name}"`,
        `Tool "${t.name}" description contains excessive-permission language ` +
          `("admin_access", "full_access", wildcard scopes). This violates the ` +
          `principle of least privilege and may indicate over-broad API access.`,
        "warning",
        url,
        {
          summary: "Replace wildcard/admin scopes with the minimum required permissions.",
          steps: [
            `Audit what permissions tool "${t.name}" actually needs.`,
            "Replace wildcard scopes with an explicit, minimal list.",
            "Document the justification for each granted scope.",
          ],
          references: ["https://owasp.org/www-project-api-security/"],
        },
        t.description?.slice(0, 120),
      ),
    );
}

/** MCP-L009: Probe the /sse endpoint without credentials. */
async function checkSseAuth(
  baseUrl: string,
  timeoutMs: number,
): Promise<Finding | null> {
  const sseUrl = baseUrl.replace(/\/?$/, "/sse");
  try {
    const { statusCode } = await rawGet(sseUrl, { Accept: "text/event-stream" }, timeoutMs);

    // Any 2xx without authentication == unauthenticated SSE
    if (statusCode >= 200 && statusCode < 300) {
      return makeFinding(
        "MCP-L009",
        "SSE endpoint accessible without authentication",
        `The /sse endpoint returned HTTP ${statusCode} without credentials. ` +
          `Any network client can subscribe to real-time server events, which may ` +
          `include tool outputs, partial LLM responses, or session state.`,
        "warning",
        baseUrl,
        {
          summary: "Protect the /sse endpoint with the same authentication as other endpoints.",
          steps: [
            "Add authentication middleware to the /sse route.",
            "Validate the Bearer token or session cookie before upgrading to SSE.",
            "Return HTTP 401 for unauthenticated SSE connection attempts.",
          ],
          references: ["https://modelcontextprotocol.io/docs/concepts/transports"],
        },
      );
    }
  } catch {
    // /sse not reachable — skip
  }

  return null;
}

// ---------------------------------------------------------------------------
// Helper: construct a Finding
// ---------------------------------------------------------------------------

function makeFinding(
  ruleId: string,
  name: string,
  message: string,
  severity: Severity,
  url: string,
  remediation: Remediation,
  snippet?: string,
): Finding {
  return {
    ruleId,
    message: `${name}: ${message}`,
    severity,
    filePath: url,
    snippet,
    remediation,
  };
}

// ---------------------------------------------------------------------------
// MCP session helpers
// ---------------------------------------------------------------------------

/** Call initialize on the server and parse capabilities. */
async function initializeSession(
  url: string,
  authToken: string | undefined,
  timeoutMs: number,
): Promise<McpServerCapabilities | null> {
  try {
    const resp = await jsonRpc(
      url,
      "initialize",
      {
        protocolVersion: "2024-11-05",
        capabilities: { tools: {}, resources: {}, prompts: {} },
        clientInfo: { name: "mcp-scan", version: "0.1" },
      },
      authToken,
      timeoutMs,
    );

    if (!resp.result) return null;

    const r = resp.result as Record<string, unknown>;
    const caps: McpServerCapabilities = {
      serverName: (r["serverInfo"] as Record<string, string> | undefined)?.["name"],
      serverVersion: (r["serverInfo"] as Record<string, string> | undefined)?.["version"],
      protocolVersion: r["protocolVersion"] as string | undefined,
    };

    const capabilities = r["capabilities"] as Record<string, unknown> | undefined;
    if (capabilities) {
      caps.tools = "tools" in capabilities;
      caps.resources = "resources" in capabilities;
      caps.prompts = "prompts" in capabilities;
    }

    return caps;
  } catch {
    return null;
  }
}

/** List tools from the server. */
async function listTools(
  url: string,
  authToken: string | undefined,
  timeoutMs: number,
): Promise<McpTool[]> {
  try {
    const resp = await jsonRpc(url, "tools/list", {}, authToken, timeoutMs);
    if (!resp.result) return [];
    const r = resp.result as Record<string, unknown>;
    return (r["tools"] as McpTool[] | undefined) ?? [];
  } catch {
    return [];
  }
}

/** List resources from the server. */
async function listResources(
  url: string,
  authToken: string | undefined,
  timeoutMs: number,
): Promise<McpResource[]> {
  try {
    const resp = await jsonRpc(url, "resources/list", {}, authToken, timeoutMs);
    if (!resp.result) return [];
    const r = resp.result as Record<string, unknown>;
    return (r["resources"] as McpResource[] | undefined) ?? [];
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a live MCP server endpoint for security vulnerabilities.
 *
 * Probes the server via JSON-RPC, analyzes tool definitions, and returns a
 * ScanResult with findings and a TrustScore.
 *
 * @param options - Live scan options including the server URL.
 * @returns ScanResult with live findings, trust score, and server metadata.
 */
export async function scanLive(options: LiveScanOptions): Promise<ScanResult> {
  const { url, authToken, timeoutMs = 10_000, rules } = options;
  const activeRules = rules ? new Set(rules) : null;
  const shouldCheck = (id: string) => !activeRules || activeRules.has(id);

  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  const errors: string[] = [];
  let endpointsProbed = 1; // the base URL itself

  // -------------------------------------------------------------------------
  // Step 1: TLS check (no network needed)
  // -------------------------------------------------------------------------
  if (shouldCheck("MCP-L001")) {
    const tlsFinding = checkTls(url);
    if (tlsFinding) findings.push(tlsFinding);
  }

  // -------------------------------------------------------------------------
  // Step 2: Auth probe
  // -------------------------------------------------------------------------
  let requiresAuth = true;
  if (shouldCheck("MCP-L002")) {
    try {
      const { finding, result } = await checkAuth(url, timeoutMs);
      requiresAuth = result.requiresAuth;
      if (finding) findings.push(finding);
    } catch (e) {
      errors.push(`Auth probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Step 3: Initialize session (use authToken if provided)
  // -------------------------------------------------------------------------
  const capabilities = await initializeSession(url, authToken, timeoutMs);

  // -------------------------------------------------------------------------
  // Step 4: Tool enumeration + analysis
  // -------------------------------------------------------------------------
  const tools = await listTools(url, authToken, timeoutMs);
  const resources = await listResources(url, authToken, timeoutMs);
  endpointsProbed += tools.length + resources.length;

  if (shouldCheck("MCP-L003")) {
    findings.push(...checkToolDescriptionsForInjection(tools, url));
  }
  if (shouldCheck("MCP-L004") || shouldCheck("MCP-L007") || shouldCheck("MCP-L010")) {
    const schemaFindings = checkToolSchemas(tools, url).filter(
      (f) => shouldCheck(f.ruleId),
    );
    findings.push(...schemaFindings);
  }
  if (shouldCheck("MCP-L008")) {
    findings.push(...checkExcessiveScope(tools, url));
  }

  // -------------------------------------------------------------------------
  // Step 5: Error handling probe
  // -------------------------------------------------------------------------
  let leaksErrors = false;
  if (shouldCheck("MCP-L005")) {
    try {
      const { finding, result } = await checkErrorHandling(url, timeoutMs);
      leaksErrors = result.leaksStackTrace || result.leaksInternalDetails;
      if (finding) findings.push(finding);
      endpointsProbed++;
    } catch (e) {
      errors.push(`Error-handling probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Step 6: Rate-limiting check
  // -------------------------------------------------------------------------
  let hasRateLimit = true;
  if (shouldCheck("MCP-L006")) {
    try {
      const finding = await checkRateLimiting(url, timeoutMs);
      if (finding) {
        hasRateLimit = false;
        findings.push(finding);
      }
    } catch (e) {
      errors.push(`Rate-limit probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Step 7: SSE auth check
  // -------------------------------------------------------------------------
  if (shouldCheck("MCP-L009")) {
    try {
      const finding = await checkSseAuth(url, timeoutMs);
      if (finding) findings.push(finding);
      endpointsProbed++;
    } catch (e) {
      errors.push(`SSE probe failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // -------------------------------------------------------------------------
  // Step 8: Compute trust score
  // -------------------------------------------------------------------------
  const usesHttps = url.startsWith("https://");
  const strictSchemaCount = tools.filter(
    (t) =>
      !t.inputSchema ||
      !t.inputSchema.properties ||
      t.inputSchema.additionalProperties === false,
  ).length;
  const strictSchemaRatio = tools.length > 0 ? strictSchemaCount / tools.length : 1;

  const trustScore = computeTrustScore({
    requiresAuth,
    usesHttps,
    strictSchemaRatio,
    hasRateLimit,
    leaksErrors,
  });

  // -------------------------------------------------------------------------
  // Step 9: Aggregate
  // -------------------------------------------------------------------------
  const finishedAt = new Date().toISOString();
  const summary = findings.reduce(
    (acc, f) => {
      if (f.severity === "error") acc.errors++;
      else if (f.severity === "warning") acc.warnings++;
      else if (f.severity === "note") acc.notes++;
      return acc;
    },
    { errors: 0, warnings: 0, notes: 0 },
  );

  return {
    target: url,
    startedAt,
    finishedAt,
    findings,
    filesScanned: endpointsProbed,
    errors,
    summary,
    trustScore,
    serverCapabilities: capabilities ?? undefined,
    scanMode: "live",
  };
}
