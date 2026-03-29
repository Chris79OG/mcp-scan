import { Rule } from "../types";

/**
 * The 10 MCP CVE detection rules.
 *
 * Rules are based on:
 * - 7 divergence patterns (A-G) from MCP Contract Lab
 * - Known MCP CVEs from the Syntrophy Radar signals
 *
 * Severity assignments:
 *   error   — MCP-001, MCP-003, MCP-006, MCP-010
 *   warning — MCP-002, MCP-004, MCP-005, MCP-007, MCP-008, MCP-009
 */
export const RULES: Rule[] = [
  {
    id: "MCP-001",
    name: "Prompt injection via tool description",
    description:
      "A tool description contains text that attempts to hijack the LLM's behavior via embedded instructions (Pattern A). Attackers embed commands like 'ignore previous instructions' inside tool metadata to override system prompts.",
    defaultSeverity: "error",
    helpUri: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    pattern: {
      type: "regex",
      value:
        "(?i)(ignore\\s+(previous|all|prior)\\s+instructions?|disregard\\s+(previous|all)\\s+instructions?|you\\s+are\\s+now\\s+a|act\\s+as\\s+if\\s+you|forget\\s+your\\s+(previous|prior|all)\\s+(instructions?|training)|\\[SYSTEM\\]|<system>|\\|JAILBREAK\\|)",
      fileTypes: [".json", ".ts", ".js", ".yaml", ".yml"],
    },
  },
  {
    id: "MCP-002",
    name: "Excessive scope/permission grants",
    description:
      "A tool or resource definition grants overly broad permissions (Pattern B). Requesting wildcard scopes or administrative access without narrower alternatives violates least-privilege principles.",
    defaultSeverity: "warning",
    pattern: {
      type: "regex",
      value:
        "(?i)(scope[s]?\\s*[=:\"']\\s*[*\"']\\*[\"']|permissions?\\s*[=:\"']\\s*[\"']?\\*[\"']?|admin(?:istrator)?_access\\s*[=:\"']\\s*true|full_access\\s*[=:\"']\\s*true|grant_all|allow_all_scopes)",
      fileTypes: [".json", ".ts", ".js", ".yaml", ".yml"],
    },
  },
  {
    id: "MCP-003",
    name: "Untrusted tool call poisoning via system prompt",
    description:
      "A tool injects content into the system prompt via an untrusted callback or dynamic template (Pattern C). This allows server-side injection that persists across the user's session.",
    defaultSeverity: "error",
    pattern: {
      type: "regex",
      value:
        "(?i)(systemPrompt\\s*[+]=|system_prompt\\s*[+]=|messages\\.unshift.*role.*system|prompt\\.prepend|inject.*system.*prompt|system.*template.*\\$\\{.*\\})",
      fileTypes: [".ts", ".js"],
    },
  },
  {
    id: "MCP-004",
    name: "Unvalidated tool input schema",
    description:
      "A JSON Schema tool definition is missing `additionalProperties: false` (Pattern D). Without this constraint, clients can pass arbitrary undeclared properties that bypass server-side validation.",
    defaultSeverity: "warning",
    pattern: {
      type: "keyword",
      value: "additionalProperties",
      fileTypes: [".json", ".yaml", ".yml"],
    },
  },
  {
    id: "MCP-005",
    name: "Secret exfiltration via tool callback URL",
    description:
      "A tool definition registers a callback URL that is parameterized with sensitive request data (Pattern E). Secrets, session tokens, or user data may be leaked to an attacker-controlled endpoint.",
    defaultSeverity: "warning",
    pattern: {
      type: "regex",
      value:
        "(?i)(callback_url|webhook_url|notify_url|redirect_uri)\\s*[=:\"'].*\\$\\{|callback.*url.*\\+\\s*(?:token|secret|key|auth|session|apikey)",
      fileTypes: [".ts", ".js", ".json", ".yaml", ".yml"],
    },
  },
  {
    id: "MCP-006",
    name: "SSRF via unsanitized resource URI",
    description:
      "A resource or tool handler constructs a URL from user-supplied parameters without validation (Pattern F). An attacker can cause the MCP server to make requests to internal services.",
    defaultSeverity: "error",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:fetch|axios\\.get|https?\\.get|request\\.get)\\s*\\(\\s*(?:params\\.|req\\.|input\\.|args\\.|options\\.)[a-zA-Z_][a-zA-Z0-9_.]*|new URL\\(\\s*(?:params\\.|req\\.|input\\.)|url:\\s*`[^`]*\\$\\{(?:params|req|input|args|options)\\.",
      fileTypes: [".ts", ".js"],
    },
  },
  {
    id: "MCP-007",
    name: "Community reimplementation divergence marker",
    description:
      "A known incompatible fork pattern or divergence marker from the MCP community reimplementation space detected (Pattern G). These indicate non-spec implementations that may have different security semantics.",
    defaultSeverity: "warning",
    pattern: {
      type: "regex",
      value:
        "(?i)(@modelcontextprotocol\\/sdk-(?!\\d)|mcp-server-unofficial|mcp-unofficial|forked-mcp|custom-mcp-protocol)",
      fileTypes: [".json", ".ts", ".js"],
    },
  },
  {
    id: "MCP-008",
    name: "Insecure SSE transport — missing auth on /sse endpoint",
    description:
      "The MCP server exposes a Server-Sent Events (SSE) endpoint without authentication middleware. Any client on the network can subscribe to real-time events.",
    defaultSeverity: "warning",
    pattern: {
      type: "regex",
      value:
        "(?i)(app\\.get|router\\.get|server\\.get)\\s*\\(\\s*[\"'`]\\/sse[\"'`](?![^)]*(?:auth|middleware|authenticate|requireAuth|verifyToken))",
      fileTypes: [".ts", ".js"],
    },
  },
  {
    id: "MCP-009",
    name: "Missing tool output sanitization",
    description:
      "Raw LLM output is passed directly to another tool call without sanitization. This creates a prompt injection amplification path where earlier injections propagate forward.",
    defaultSeverity: "warning",
    pattern: {
      type: "regex",
      value:
        "(?i)(llm(?:Output|Response|Result)|completion\\.choices\\[0\\]\\.(?:message\\.content|text))\\s*[,)]\\s*(?:await\\s+)?(?:tool|call|invoke|execute|run)\\(",
      fileTypes: [".ts", ".js"],
    },
  },
  {
    id: "MCP-010",
    name: "Unrestricted filesystem access",
    description:
      "A tool handler accepts a file path parameter without an explicit allowlist or path sanitization. An attacker can read arbitrary files from the server filesystem.",
    defaultSeverity: "error",
    pattern: {
      type: "regex",
      value:
        "(?i)(fs\\.readFile|fs\\.writeFile|fs\\.readFileSync|fs\\.writeFileSync|fs\\.createReadStream|fs\\.createWriteStream)\\s*\\(\\s*(?:params\\.|req\\.|input\\.|args\\.|options\\.|(?:file|dir)?[Pp]ath\\b|fileName\\b)",
      fileTypes: [".ts", ".js"],
    },
  },
];

/** Lookup a rule by its ID. Returns undefined if not found. */
export function getRuleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}
