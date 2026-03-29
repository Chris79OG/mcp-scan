// ---------------------------------------------------------------------------
// Types mirrored from the mcp-scan API — keep in sync with openapi.yaml
// ---------------------------------------------------------------------------

export type Severity = "error" | "warning" | "note" | "none";

export interface Finding {
  ruleId: string;
  message: string;
  severity: Severity;
  filePath: string;
  line?: number;
  column?: number;
  snippet?: string;
}

export interface FindingSummary {
  errors: number;
  warnings: number;
  notes: number;
}

export interface ScanResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  findings: Finding[];
  filesScanned: number;
  errors: string[];
  summary: FindingSummary;
}

export type ScanJobStatus = "queued" | "running" | "completed" | "failed";

export interface ScanJob {
  id: string;
  target: string;
  rules?: string[];
  status: ScanJobStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: ScanResult;
  error?: string;
}

export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export type WebhookEvent = "scan.completed" | "scan.failed" | "scan.critical_finding";

export interface WebhookConfig {
  id: string;
  url: string;
  events: WebhookEvent[];
  secret?: string;
  createdAt: string;
}

export interface CreateScanRequest {
  target: string;
  rules?: string[];
  webhookUrl?: string;
}

export interface CreateWebhookRequest {
  url: string;
  events: WebhookEvent[];
  secret?: string;
}

export interface ListScansOptions {
  page?: number;
  pageSize?: number;
  status?: ScanJobStatus;
}

export interface MpcScanClientOptions {
  /** Base URL of the mcp-scan API server, e.g. http://localhost:3001 */
  baseUrl: string;
  /** Optional API key sent as Authorization: Bearer <key> */
  apiKey?: string;
  /** Request timeout in milliseconds (default: 30000) */
  timeoutMs?: number;
}

export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
}
