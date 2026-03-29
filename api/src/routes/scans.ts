import { Router, Request, Response, NextFunction } from "express";
import { v4 as uuidv4 } from "uuid";
import { scan } from "@syntrophy/mcp-scan";
import { store } from "../services/store";
import { dispatch } from "../services/webhook";
import type { CreateScanRequest, ScanJob } from "../types";

export const scansRouter = Router();

// ---------------------------------------------------------------------------
// POST /scans — initiate a new scan
// ---------------------------------------------------------------------------
scansRouter.post("/", async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const body = req.body as CreateScanRequest;

  if (!body.target || typeof body.target !== "string" || !body.target.trim()) {
    res.status(400).json({
      error: "INVALID_REQUEST",
      message: "Field 'target' is required and must be a non-empty string.",
      statusCode: 400,
    });
    return;
  }

  const job: ScanJob = {
    id: uuidv4(),
    target: body.target.trim(),
    rules: Array.isArray(body.rules) ? body.rules : undefined,
    status: "queued",
    createdAt: new Date().toISOString(),
  };

  store.set(job);

  // Run the scan asynchronously — do not await
  runScanAsync(job, body.webhookUrl).catch((err) => {
    console.error(`[scan] unhandled error for job ${job.id}:`, err);
  });

  res.status(202).json(job);
});

// ---------------------------------------------------------------------------
// GET /scans — list scan history
// ---------------------------------------------------------------------------
scansRouter.get("/", (req: Request, res: Response): void => {
  const page = parseInt(String(req.query.page ?? "1"), 10);
  const pageSize = parseInt(String(req.query.pageSize ?? "20"), 10);
  const statusFilter = req.query.status as ScanJob["status"] | undefined;

  if (isNaN(page) || page < 1) {
    res.status(400).json({ error: "INVALID_PARAM", message: "page must be a positive integer", statusCode: 400 });
    return;
  }
  if (isNaN(pageSize) || pageSize < 1 || pageSize > 100) {
    res.status(400).json({ error: "INVALID_PARAM", message: "pageSize must be between 1 and 100", statusCode: 400 });
    return;
  }

  const { items, total } = store.list({ page, pageSize, status: statusFilter });

  res.setHeader("X-Total-Count", total.toString());
  res.setHeader("X-Page", page.toString());
  res.setHeader("X-Page-Size", pageSize.toString());

  res.json({
    items,
    total,
    page,
    pageSize,
  });
});

// ---------------------------------------------------------------------------
// GET /scans/:id — get scan status
// ---------------------------------------------------------------------------
scansRouter.get("/:id", (req: Request, res: Response): void => {
  const job = store.get(req.params.id);
  if (!job) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Scan job '${req.params.id}' not found.`,
      statusCode: 404,
    });
    return;
  }
  res.json(job);
});

// ---------------------------------------------------------------------------
// GET /scans/:id/results — get scan results (only when completed)
// ---------------------------------------------------------------------------
scansRouter.get("/:id/results", (req: Request, res: Response): void => {
  const job = store.get(req.params.id);
  if (!job) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Scan job '${req.params.id}' not found.`,
      statusCode: 404,
    });
    return;
  }

  if (job.status === "queued" || job.status === "running") {
    res.status(202).json({
      error: "SCAN_IN_PROGRESS",
      message: `Scan '${job.id}' is still ${job.status}. Poll GET /scans/${job.id} for status.`,
      statusCode: 202,
      scanId: job.id,
      status: job.status,
    });
    return;
  }

  if (job.status === "failed") {
    res.status(422).json({
      error: "SCAN_FAILED",
      message: job.error ?? "Scan failed with an unknown error.",
      statusCode: 422,
      scanId: job.id,
    });
    return;
  }

  // completed
  res.json(job.result);
});

// ---------------------------------------------------------------------------
// DELETE /scans/:id — cancel or remove a scan record
// ---------------------------------------------------------------------------
scansRouter.delete("/:id", (req: Request, res: Response): void => {
  const job = store.get(req.params.id);
  if (!job) {
    res.status(404).json({
      error: "NOT_FOUND",
      message: `Scan job '${req.params.id}' not found.`,
      statusCode: 404,
    });
    return;
  }

  if (job.status === "running") {
    res.status(409).json({
      error: "CONFLICT",
      message: "Cannot delete a scan that is currently running.",
      statusCode: 409,
    });
    return;
  }

  store.delete(req.params.id);
  res.status(204).send();
});

// ---------------------------------------------------------------------------
// Internal: run a scan job asynchronously and update store + dispatch webhooks
// ---------------------------------------------------------------------------
async function runScanAsync(job: ScanJob, oneOffWebhookUrl?: string): Promise<void> {
  store.update(job.id, { status: "running", startedAt: new Date().toISOString() });

  try {
    const result = await scan({
      input: job.target,
      rules: job.rules,
    });

    const completedJob = store.update(job.id, {
      status: "completed",
      completedAt: new Date().toISOString(),
      result,
    });

    if (completedJob) {
      dispatch("scan.completed", completedJob, oneOffWebhookUrl);

      // Dispatch critical finding alert if any errors were found
      if (result.summary.errors > 0) {
        dispatch("scan.critical_finding", completedJob, oneOffWebhookUrl);
      }
    }
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const failedJob = store.update(job.id, {
      status: "failed",
      completedAt: new Date().toISOString(),
      error: errorMsg,
    });
    if (failedJob) {
      dispatch("scan.failed", failedJob, oneOffWebhookUrl);
    }
  }
}
