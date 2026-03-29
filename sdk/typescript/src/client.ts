import type {
  ScanJob,
  ScanResult,
  WebhookConfig,
  PaginatedList,
  CreateScanRequest,
  CreateWebhookRequest,
  ListScansOptions,
  MpcScanClientOptions,
  ApiError,
} from "./types";

/** Error thrown when the API returns a non-2xx response. */
export class McpScanApiError extends Error {
  public readonly statusCode: number;
  public readonly errorCode: string;

  constructor(body: ApiError) {
    super(body.message);
    this.name = "McpScanApiError";
    this.statusCode = body.statusCode;
    this.errorCode = body.error;
  }
}

/**
 * Typed client for the mcp-scan REST API.
 *
 * Uses the built-in `fetch` API (Node 18+). Pass a custom `fetch` via options
 * if you need polyfilling in older environments.
 *
 * @example
 * ```ts
 * import { McpScanClient } from "@syntrophy/mcp-scan-client";
 *
 * const client = new McpScanClient({ baseUrl: "http://localhost:3001" });
 *
 * // Trigger a scan
 * const job = await client.scans.create({ target: "/path/to/mcp-server" });
 *
 * // Poll until done
 * const result = await client.scans.waitForResult(job.id);
 * console.log(`Found ${result.summary.errors} error(s)`);
 * ```
 */
export class McpScanClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;

  public readonly scans: ScansClient;
  public readonly webhooks: WebhooksClient;

  constructor(options: MpcScanClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.headers = { "Content-Type": "application/json" };
    if (options.apiKey) {
      this.headers["Authorization"] = `Bearer ${options.apiKey}`;
    }
    this.scans = new ScansClient(this);
    this.webhooks = new WebhooksClient(this);
  }

  /** @internal */
  async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await fetch(url, {
        method,
        headers: this.headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }

    let json: unknown;
    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      json = await res.json();
    } else {
      json = await res.text();
    }

    if (!res.ok) {
      const errBody = json as ApiError;
      throw new McpScanApiError({
        error: errBody?.error ?? "UNKNOWN_ERROR",
        message: errBody?.message ?? `HTTP ${res.status}`,
        statusCode: res.status,
      });
    }

    return json as T;
  }

  /** Check server health. */
  async health(): Promise<{ status: string; version: string; timestamp: string }> {
    return this.request("GET", "/health");
  }
}

// ---------------------------------------------------------------------------
// Scans sub-client
// ---------------------------------------------------------------------------

export class ScansClient {
  constructor(private readonly client: McpScanClient) {}

  /** Initiate a new scan job. Returns immediately with status `queued`. */
  async create(req: CreateScanRequest): Promise<ScanJob> {
    return this.client.request<ScanJob>("POST", "/scans", req);
  }

  /** List scan history with optional filtering and pagination. */
  async list(opts: ListScansOptions = {}): Promise<PaginatedList<ScanJob>> {
    const params = new URLSearchParams();
    if (opts.page) params.set("page", String(opts.page));
    if (opts.pageSize) params.set("pageSize", String(opts.pageSize));
    if (opts.status) params.set("status", opts.status);
    const qs = params.toString() ? `?${params}` : "";
    return this.client.request<PaginatedList<ScanJob>>("GET", `/scans${qs}`);
  }

  /** Get the current state of a scan job. */
  async get(scanId: string): Promise<ScanJob> {
    return this.client.request<ScanJob>("GET", `/scans/${scanId}`);
  }

  /** Retrieve the full scan results for a completed scan. */
  async getResults(scanId: string): Promise<ScanResult> {
    return this.client.request<ScanResult>("GET", `/scans/${scanId}/results`);
  }

  /** Delete a scan record. The scan must not be running. */
  async delete(scanId: string): Promise<void> {
    await this.client.request<void>("DELETE", `/scans/${scanId}`);
  }

  /**
   * Poll a scan job until it reaches `completed` or `failed` status.
   *
   * @param scanId - ID of the scan to wait for.
   * @param options.intervalMs - Polling interval in ms (default 2000).
   * @param options.maxWaitMs - Maximum total wait time in ms (default 300000).
   * @throws {Error} if the scan fails or the timeout is reached.
   */
  async waitForResult(
    scanId: string,
    options: { intervalMs?: number; maxWaitMs?: number } = {},
  ): Promise<ScanResult> {
    const intervalMs = options.intervalMs ?? 2_000;
    const maxWaitMs = options.maxWaitMs ?? 300_000;
    const deadline = Date.now() + maxWaitMs;

    while (Date.now() < deadline) {
      const job = await this.get(scanId);

      if (job.status === "completed") {
        return this.getResults(scanId);
      }

      if (job.status === "failed") {
        throw new Error(`Scan ${scanId} failed: ${job.error ?? "unknown error"}`);
      }

      await sleep(intervalMs);
    }

    throw new Error(`Timed out waiting for scan ${scanId} after ${maxWaitMs}ms`);
  }
}

// ---------------------------------------------------------------------------
// Webhooks sub-client
// ---------------------------------------------------------------------------

export class WebhooksClient {
  constructor(private readonly client: McpScanClient) {}

  /** Register a new webhook. */
  async create(req: CreateWebhookRequest): Promise<WebhookConfig> {
    return this.client.request<WebhookConfig>("POST", "/webhooks", req);
  }

  /** List all registered webhooks. */
  async list(): Promise<WebhookConfig[]> {
    return this.client.request<WebhookConfig[]>("GET", "/webhooks");
  }

  /** Get a webhook by ID. */
  async get(webhookId: string): Promise<WebhookConfig> {
    return this.client.request<WebhookConfig>("GET", `/webhooks/${webhookId}`);
  }

  /** Unregister a webhook. */
  async delete(webhookId: string): Promise<void> {
    await this.client.request<void>("DELETE", `/webhooks/${webhookId}`);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
