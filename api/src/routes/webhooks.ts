import { Router, Request, Response } from "express";
import {
  registerWebhook,
  unregisterWebhook,
  listWebhooks,
  getWebhook,
} from "../services/webhook";
import type { WebhookEvent } from "../types";

export const webhooksRouter = Router();

const VALID_EVENTS: WebhookEvent[] = ["scan.completed", "scan.failed", "scan.critical_finding"];

// ---------------------------------------------------------------------------
// POST /webhooks — register a new webhook
// ---------------------------------------------------------------------------
webhooksRouter.post("/", (req: Request, res: Response): void => {
  const { url, events, secret } = req.body as {
    url?: unknown;
    events?: unknown;
    secret?: unknown;
  };

  if (!url || typeof url !== "string" || !url.trim()) {
    res.status(400).json({
      error: "INVALID_REQUEST",
      message: "Field 'url' is required and must be a non-empty string.",
      statusCode: 400,
    });
    return;
  }

  // Validate URL format
  try {
    new URL(url);
  } catch {
    res.status(400).json({
      error: "INVALID_URL",
      message: "Field 'url' must be a valid URL (http or https).",
      statusCode: 400,
    });
    return;
  }

  if (!Array.isArray(events) || events.length === 0) {
    res.status(400).json({
      error: "INVALID_REQUEST",
      message: `Field 'events' must be a non-empty array. Valid values: ${VALID_EVENTS.join(", ")}`,
      statusCode: 400,
    });
    return;
  }

  const invalidEvents = (events as unknown[]).filter((e) => !VALID_EVENTS.includes(e as WebhookEvent));
  if (invalidEvents.length > 0) {
    res.status(400).json({
      error: "INVALID_EVENTS",
      message: `Unknown event(s): ${invalidEvents.join(", ")}. Valid values: ${VALID_EVENTS.join(", ")}`,
      statusCode: 400,
    });
    return;
  }

  const config = registerWebhook(
    url.trim(),
    events as WebhookEvent[],
    typeof secret === "string" && secret ? secret : undefined,
  );

  res.status(201).json(config);
});

// ---------------------------------------------------------------------------
// GET /webhooks — list all registered webhooks
// ---------------------------------------------------------------------------
webhooksRouter.get("/", (_req: Request, res: Response): void => {
  res.json(listWebhooks());
});

// ---------------------------------------------------------------------------
// GET /webhooks/:id — get one webhook
// ---------------------------------------------------------------------------
webhooksRouter.get("/:id", (req: Request, res: Response): void => {
  const wh = getWebhook(req.params.id);
  if (!wh) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Webhook '${req.params.id}' not found.`,
      statusCode: 404,
    });
    return;
  }
  res.json(wh);
});

// ---------------------------------------------------------------------------
// DELETE /webhooks/:id — unregister a webhook
// ---------------------------------------------------------------------------
webhooksRouter.delete("/:id", (req: Request, res: Response): void => {
  const existed = unregisterWebhook(req.params.id);
  if (!existed) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Webhook '${req.params.id}' not found.`,
      statusCode: 404,
    });
    return;
  }
  res.status(204).send();
});
