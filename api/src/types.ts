import type { ScanResult } from "@syntrophy/mcp-scan";

/** Status of an async scan job. */
export type ScanJobStatus = "queued" | "running" | "completed" | "failed";

/** A registered webhook endpoint. */
export interface WebhookConfig {
  id: string;
  url: string;
  /** Events this webhook listens to. */
  events: WebhookEvent[];
  /** Optional secret for HMAC signature header (X-MCP-Scan-Signature). */
  secret?: string;
  createdAt: string;
}

export type WebhookEvent = "scan.completed" | "scan.failed" | "scan.critical_finding";

/** Payload delivered to a webhook endpoint. */
export interface WebhookPayload {
  event: WebhookEvent;
  scanId: string;
  timestamp: string;
  data: ScanJob;
}

/** A scan job record stored server-side. */
export interface ScanJob {
  id: string;
  target: string;
  /** Optional list of rule IDs to restrict scanning. */
  rules?: string[];
  status: ScanJobStatus;
  createdAt: string;
  startedAt?: string;
  completedAt?: string;
  result?: ScanResult;
  error?: string;
}

/** Request body for POST /scans */
export interface CreateScanRequest {
  /** Local path or remote URL to scan. */
  target: string;
  /** Optional specific rule IDs to apply. */
  rules?: string[];
  /** Optional webhook URL to notify on completion (one-off). */
  webhookUrl?: string;
}

/** Paginated list response wrapper. */
export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

/** Standard API error response. */
export interface ApiError {
  error: string;
  message: string;
  statusCode: number;
}
