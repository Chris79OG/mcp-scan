import * as crypto from "crypto";
import * as http from "http";
import * as https from "https";
import type { WebhookConfig, WebhookEvent, WebhookPayload, ScanJob } from "../types";
import { v4 as uuidv4 } from "uuid";

/** In-memory webhook registry. */
const webhooks: Map<string, WebhookConfig> = new Map();

/** Register a new webhook. Returns the created config. */
export function registerWebhook(
  url: string,
  events: WebhookEvent[],
  secret?: string,
): WebhookConfig {
  const config: WebhookConfig = {
    id: uuidv4(),
    url,
    events,
    secret,
    createdAt: new Date().toISOString(),
  };
  webhooks.set(config.id, config);
  return config;
}

/** Deregister a webhook by ID. Returns true if it existed. */
export function unregisterWebhook(id: string): boolean {
  return webhooks.delete(id);
}

/** List all registered webhooks. */
export function listWebhooks(): WebhookConfig[] {
  return Array.from(webhooks.values()).map((w) => ({ ...w }));
}

/** Get one webhook by ID. */
export function getWebhook(id: string): WebhookConfig | undefined {
  const w = webhooks.get(id);
  return w ? { ...w } : undefined;
}

/**
 * Dispatch an event to all registered webhooks that subscribe to it.
 *
 * Fires-and-forgets — failures are logged but do not throw.
 * Also accepts an optional one-off URL to notify (from the scan request).
 */
export function dispatch(
  event: WebhookEvent,
  job: ScanJob,
  oneOffUrl?: string,
): void {
  const payload: WebhookPayload = {
    event,
    scanId: job.id,
    timestamp: new Date().toISOString(),
    data: job,
  };
  const body = JSON.stringify(payload);

  // Registered webhooks
  for (const wh of webhooks.values()) {
    if (wh.events.includes(event)) {
      sendWebhook(wh.url, body, wh.secret).catch((err) => {
        console.error(`[webhook] delivery failed to ${wh.url}:`, err instanceof Error ? err.message : err);
      });
    }
  }

  // One-off URL provided inline with the scan request
  if (oneOffUrl) {
    sendWebhook(oneOffUrl, body).catch((err) => {
      console.error(`[webhook] one-off delivery failed to ${oneOffUrl}:`, err instanceof Error ? err.message : err);
    });
  }
}

/** Send a single HTTP POST to a webhook URL. */
async function sendWebhook(url: string, body: string, secret?: string): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(body).toString(),
    "User-Agent": "mcp-scan-api/0.1.0",
    "X-MCP-Scan-Event": "true",
  };

  if (secret) {
    const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
    headers["X-MCP-Scan-Signature"] = `sha256=${sig}`;
  }

  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === "https:" ? https : http;
    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: "POST",
        headers,
        timeout: 10_000,
      },
      (res) => {
        res.resume(); // drain
        if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`HTTP ${res.statusCode}`));
        }
      },
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("webhook request timed out"));
    });

    req.write(body);
    req.end();
  });
}
