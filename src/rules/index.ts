import { Rule } from "../types";

/**
 * The 15 MCP CVE detection rules.
 *
 * Rules are based on:
 * - 7 divergence patterns (A-G) from MCP Contract Lab
 * - Known MCP CVEs from the Syntrophy Radar signals
 * - OWASP Top 10 for LLM Applications
 *
 * Severity assignments:
 *   error   — MCP-001, MCP-003, MCP-006, MCP-010, MCP-011, MCP-012
 *   warning — MCP-002, MCP-004, MCP-005, MCP-007, MCP-008, MCP-009, MCP-013, MCP-014, MCP-015
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
    remediation: {
      summary: "Remove embedded instruction-override text from all tool descriptions.",
      steps: [
        "Search the codebase for all tool description strings.",
        "Remove any text that instructs the LLM to ignore, override, or forget previous instructions.",
        "Add a CI lint step that rejects tool definitions matching the injection pattern.",
        "Consider a static analysis gate using mcp-scan rule MCP-001 in your pipeline.",
      ],
      references: [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      ],
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
    remediation: {
      summary: "Replace wildcard or admin scopes with the minimum required permission set.",
      steps: [
        "Enumerate the exact API operations this tool needs to perform.",
        "Replace `*` or `admin` scopes with a specific, minimal list of scopes.",
        "Document the justification for each granted scope in a comment.",
        "Review scope grants as part of your regular security audit cycle.",
      ],
      references: ["https://owasp.org/www-project-api-security/"],
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
    remediation: {
      summary: "Never build system prompts by concatenating untrusted external content.",
      steps: [
        "Identify every location where the system prompt is constructed or modified.",
        "Replace string concatenation with a parameterized template where user/tool content is a variable, not code.",
        "Sanitize any external content before it is inserted into the prompt context.",
        "Add integration tests that verify injected tool output cannot modify the system role.",
      ],
      references: [
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
      ],
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
    remediation: {
      summary: 'Add `"additionalProperties": false` to every tool input schema.',
      steps: [
        'Find all JSON Schema objects that define a "properties" key.',
        'Add `"additionalProperties": false` at the same level as "properties".',
        "Run schema validation tests to confirm extra fields are rejected.",
        "Consider using a schema validation library (Ajv, Zod) that enforces this automatically.",
      ],
      references: [
        "https://json-schema.org/understanding-json-schema/reference/object.html",
        "https://ajv.js.org/",
      ],
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
    remediation: {
      summary: "Never append secrets or tokens to callback/webhook URLs.",
      steps: [
        "Remove all secret material from callback URL construction.",
        "Deliver secrets through signed, short-lived POST request bodies instead of URL parameters.",
        "Validate that callback URLs point to allowlisted domains before invoking them.",
        "Rotate any secrets that may have been exposed via URLs.",
      ],
      references: [
        "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
      ],
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
    remediation: {
      summary: "Validate all user-supplied URLs against an allowlist before making outbound requests.",
      steps: [
        "Parse the user-supplied value as a URL object.",
        "Reject any URL whose scheme is not http or https.",
        "Reject URLs that resolve to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, ::1).",
        "Maintain an explicit allowlist of permitted hostnames; reject everything else.",
        "Return a structured error (not a stack trace) when a URL is blocked.",
      ],
      references: [
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
      ],
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
    remediation: {
      summary: "Migrate to the official @modelcontextprotocol/sdk package.",
      steps: [
        "Replace the unofficial package reference with `@modelcontextprotocol/sdk`.",
        "Run `npm install @modelcontextprotocol/sdk` and remove the unofficial dependency.",
        "Review the MCP protocol changelog for any behavioral differences between the fork and the spec.",
        "Run the full test suite to verify no regressions.",
      ],
      references: [
        "https://modelcontextprotocol.io/",
        "https://www.npmjs.com/package/@modelcontextprotocol/sdk",
      ],
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
    remediation: {
      summary: "Add authentication middleware to the /sse route before the SSE handler.",
      steps: [
        "Create or reuse an auth middleware that validates a Bearer token or session cookie.",
        "Apply the middleware to the /sse route: `app.get('/sse', authMiddleware, sseHandler)`.",
        "Return HTTP 401 for unauthenticated SSE connection attempts.",
        "Add an integration test that verifies unauthenticated SSE connections are rejected.",
      ],
      references: ["https://modelcontextprotocol.io/docs/concepts/transports"],
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
    remediation: {
      summary: "Sanitize LLM output before passing it to any downstream tool call.",
      steps: [
        "Identify all locations where LLM output is passed as an argument to a tool call.",
        "Add a sanitization step that strips or escapes instruction-override patterns from the LLM output.",
        "Consider treating LLM output as untrusted user input for downstream tool invocations.",
        "Add tests that verify injected text in LLM output does not affect subsequent tool behavior.",
      ],
      references: [
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "https://genai.owasp.org/llmrisk/llm01-prompt-injection/",
      ],
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
    remediation: {
      summary: "Restrict file access to an allowlisted base directory and sanitize path inputs.",
      steps: [
        "Define a `BASE_DIR` constant with the only directory the tool is permitted to access.",
        "Resolve the user-supplied path to an absolute path with `path.resolve(BASE_DIR, userPath)`.",
        "Verify the resolved path starts with `BASE_DIR` — reject it if not.",
        "Reject paths containing `..` before resolution as an additional defense-in-depth measure.",
        "Run the MCP server process with a least-privilege OS user that cannot access sensitive directories.",
      ],
      references: [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
      ],
    },
  },
  {
    id: "MCP-011",
    name: "Hardcoded credentials or secrets",
    description:
      "A hardcoded API key, password, secret, or token is present in source code or configuration. Credentials embedded in code are trivially exposed via version control, logs, or binary inspection.",
    defaultSeverity: "error",
    helpUri: "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:api[_-]?key|apikey|auth[_-]?token|access[_-]?token|secret[_-]?key|password|passwd|private[_-]?key|client[_-]?secret)\\s*[=:\"']\\s*[\"']?[A-Za-z0-9+/\\-_]{16,}[\"']?(?!\\s*(?:process\\.env|getenv|os\\.environ|config\\.get|\\$\\{|<))",
      fileTypes: [".ts", ".js", ".json", ".yaml", ".yml"],
    },
    remediation: {
      summary: "Move all credentials to environment variables or a secrets manager.",
      steps: [
        "Remove the hardcoded value from source code and configuration files.",
        "Replace with `process.env.SECRET_NAME` or equivalent environment variable reference.",
        "Add the secret name to `.env.example` with a placeholder value (e.g., `API_KEY=your-key-here`).",
        "Add `.env` and any secrets files to `.gitignore`.",
        "Rotate the exposed credential immediately if it was committed to any version control history.",
        "Consider using a dedicated secrets manager (HashiCorp Vault, AWS Secrets Manager) for production.",
      ],
      references: [
        "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials",
        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
      ],
    },
  },
  {
    id: "MCP-012",
    name: "Insecure code evaluation (eval/Function constructor)",
    description:
      "User-controlled or tool-sourced data is passed to `eval()`, `new Function()`, or `vm.runInNewContext()`. This allows remote code execution if an attacker can influence the input.",
    defaultSeverity: "error",
    helpUri: "https://owasp.org/www-community/attacks/Code_Injection",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:eval|new\\s+Function|vm\\.runInNewContext|vm\\.runInThisContext|vm\\.Script)\\s*\\(\\s*(?:params\\.|req\\.|input\\.|args\\.|options\\.|(?:user|tool|mcp|llm)[A-Za-z]*\\b)",
      fileTypes: [".ts", ".js"],
    },
    remediation: {
      summary: "Never execute user-supplied or tool-sourced strings as code.",
      steps: [
        "Remove all uses of `eval()` and `new Function()` that accept external input.",
        "Replace dynamic code execution with a safe data-driven approach (e.g., lookup tables, JSON configuration).",
        "If a scripting sandbox is required, use a dedicated isolated runtime (e.g., `isolated-vm`) with strict resource limits.",
        "Add a static analysis rule to your CI pipeline that rejects any new `eval()` usage.",
      ],
      references: [
        "https://owasp.org/www-community/attacks/Code_Injection",
        "https://nodejs.org/api/vm.html#security-caveats",
      ],
    },
  },
  {
    id: "MCP-013",
    name: "Cleartext HTTP endpoint in tool or resource definition",
    description:
      "A tool or resource definition references an `http://` URL (non-TLS). Data transmitted over cleartext HTTP is vulnerable to interception, modification, and credential theft.",
    defaultSeverity: "warning",
    helpUri: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:endpoint|baseUrl|base_url|serverUrl|server_url|apiUrl|api_url|callbackUrl|callback_url|webhookUrl|webhook_url)\\s*[=:\"']\\s*[\"']?http:\\/\\/(?!localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\[::1\\])",
      fileTypes: [".ts", ".js", ".json", ".yaml", ".yml"],
    },
    remediation: {
      summary: "Replace all production `http://` URLs with `https://` equivalents.",
      steps: [
        "Search for `http://` URLs in all tool and resource definitions.",
        "Replace with `https://` for all non-localhost endpoints.",
        "Enforce HTTPS at the HTTP client level using `NODE_EXTRA_CA_CERTS` or TLS options.",
        "Add a CI check that fails on any non-localhost `http://` URL in configuration.",
      ],
      references: [
        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
      ],
    },
  },
  {
    id: "MCP-014",
    name: "Sensitive data written to logs",
    description:
      "Potentially sensitive values (tokens, passwords, secrets, SSN, credit card numbers) are passed directly to logging statements. Log files are often stored insecurely and accessible to a wide audience.",
    defaultSeverity: "warning",
    helpUri: "https://owasp.org/www-community/vulnerabilities/Insertion_of_Sensitive_Information_into_Log_File",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:console\\.log|console\\.debug|console\\.info|logger\\.(?:info|debug|warn|error)|log\\.(?:info|debug))\\s*\\([^)]*(?:password|passwd|secret|token|apikey|api_key|ssn|credit.?card|cvv|private.?key)[^)]*\\)",
      fileTypes: [".ts", ".js"],
    },
    remediation: {
      summary: "Scrub sensitive fields from log output before writing.",
      steps: [
        "Identify all log statements that include request/response bodies.",
        "Create a `redact(obj, fields)` utility that replaces sensitive field values with `[REDACTED]`.",
        "Apply the redaction utility before every log call that handles user data.",
        "Configure your logging library's built-in redaction (e.g., `pino` redact option) for defense-in-depth.",
        "Add a lint rule or test that verifies sensitive field names never appear in log output.",
      ],
      references: [
        "https://owasp.org/www-community/vulnerabilities/Insertion_of_Sensitive_Information_into_Log_File",
        "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
      ],
    },
  },
  {
    id: "MCP-015",
    name: "Path traversal via unsanitized user input",
    description:
      "A file or directory path is constructed by joining user-supplied input without verifying the result stays within a safe base directory. An attacker can escape the intended directory using `../` sequences.",
    defaultSeverity: "warning",
    helpUri: "https://owasp.org/www-community/attacks/Path_Traversal",
    pattern: {
      type: "regex",
      value:
        "(?i)(?:path\\.join|path\\.resolve)\\s*\\([^)]*(?:params\\.|req\\.|input\\.|args\\.|options\\.)[a-zA-Z_][a-zA-Z0-9_.]*",
      fileTypes: [".ts", ".js"],
    },
    remediation: {
      summary: "Validate that resolved paths remain within the intended base directory.",
      steps: [
        "After calling `path.resolve()`, assert that the result starts with the expected `BASE_DIR` prefix.",
        "Reject any path that contains `..` segments before resolution as defense-in-depth.",
        "Use `path.normalize()` to collapse redundant separators before checking.",
        "Consider using the `@nicolo-ribaudo/chdir-if-exist` or similar chroot-style libraries to enforce directory boundaries at the OS level.",
      ],
      references: [
        "https://owasp.org/www-community/attacks/Path_Traversal",
        "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
      ],
    },
  },
];

/** Lookup a rule by its ID. Returns undefined if not found. */
export function getRuleById(id: string): Rule | undefined {
  return RULES.find((r) => r.id === id);
}
