import express, { Request, Response, NextFunction } from "express";
import { scansRouter } from "./routes/scans";
import { webhooksRouter } from "./routes/webhooks";

export function createApp(): express.Application {
  const app = express();

  // -------------------------------------------------------------------------
  // Middleware
  // -------------------------------------------------------------------------
  app.use(express.json({ limit: "1mb" }));

  // Rate-limit headers (informational — actual enforcement belongs in a
  // reverse proxy/gateway layer for production)
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("X-RateLimit-Limit", "1000");
    res.setHeader("X-RateLimit-Remaining", "999");
    res.setHeader("X-RateLimit-Reset", String(Math.floor(Date.now() / 1000) + 3600));
    next();
  });

  // -------------------------------------------------------------------------
  // Health check
  // -------------------------------------------------------------------------
  app.get("/health", (_req: Request, res: Response) => {
    res.json({ status: "ok", version: "0.1.0", timestamp: new Date().toISOString() });
  });

  // -------------------------------------------------------------------------
  // API routes
  // -------------------------------------------------------------------------
  app.use("/scans", scansRouter);
  app.use("/webhooks", webhooksRouter);

  // -------------------------------------------------------------------------
  // 404 handler
  // -------------------------------------------------------------------------
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      error: "NOT_FOUND",
      message: "The requested endpoint does not exist.",
      statusCode: 404,
    });
  });

  // -------------------------------------------------------------------------
  // Error handler
  // -------------------------------------------------------------------------
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error("[server] unhandled error:", err);
    res.status(500).json({
      error: "INTERNAL_ERROR",
      message: "An unexpected error occurred.",
      statusCode: 500,
    });
  });

  return app;
}

// ---------------------------------------------------------------------------
// Standalone entry point
// ---------------------------------------------------------------------------
if (require.main === module) {
  const port = parseInt(process.env.PORT ?? "3001", 10);
  const app = createApp();
  app.listen(port, () => {
    console.log(`mcp-scan API server listening on http://localhost:${port}`);
    console.log(`  Health:   GET  http://localhost:${port}/health`);
    console.log(`  Scans:    POST http://localhost:${port}/scans`);
    console.log(`  Webhooks: POST http://localhost:${port}/webhooks`);
  });
}
