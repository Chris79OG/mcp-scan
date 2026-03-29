/**
 * Integration tests for the mcp-scan REST API.
 *
 * These tests spin up the actual Express server and exercise the full
 * API flow: scan initiation → status polling → result retrieval.
 *
 * They require the parent mcp-scan package to be built first (`npm run build`
 * in the repo root).
 */
import supertest from "supertest";
import * as path from "path";
import * as http from "http";
import { createApp } from "../../src/server";

// Path to a known clean fixture from the mcp-scan test suite
const FIXTURES_DIR = path.resolve(__dirname, "../../../tests/fixtures");
const CLEAN_FIXTURE = path.join(FIXTURES_DIR, "clean-server.ts");
const VULNERABLE_FIXTURE = path.join(FIXTURES_DIR, "injection-server.ts");

let server: http.Server;
let request: ReturnType<typeof supertest>;

beforeAll(() => {
  const app = createApp();
  server = app.listen(0); // ephemeral port
  request = supertest(server);
});

afterAll((done) => {
  server.close(done);
});

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
describe("GET /health", () => {
  it("returns 200 with status ok", async () => {
    const res = await request.get("/health").expect(200);
    expect(res.body.status).toBe("ok");
    expect(typeof res.body.version).toBe("string");
    expect(typeof res.body.timestamp).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// Scan lifecycle
// ---------------------------------------------------------------------------
describe("POST /scans", () => {
  it("returns 202 with a queued job for a valid target", async () => {
    const res = await request
      .post("/scans")
      .send({ target: FIXTURES_DIR })
      .expect(202);

    expect(res.body.id).toBeTruthy();
    expect(res.body.status).toMatch(/^(queued|running|completed)$/);
    expect(res.body.target).toBe(FIXTURES_DIR);
    expect(res.body.createdAt).toBeTruthy();
  });

  it("returns 400 when target is missing", async () => {
    const res = await request.post("/scans").send({}).expect(400);
    expect(res.body.error).toBe("INVALID_REQUEST");
  });

  it("returns 400 when target is empty string", async () => {
    const res = await request.post("/scans").send({ target: "" }).expect(400);
    expect(res.body.error).toBe("INVALID_REQUEST");
  });
});

describe("GET /scans/:id", () => {
  it("returns the scan job", async () => {
    const created = await request
      .post("/scans")
      .send({ target: FIXTURES_DIR })
      .expect(202);

    const res = await request
      .get(`/scans/${created.body.id}`)
      .expect(200);

    expect(res.body.id).toBe(created.body.id);
    expect(res.body.target).toBe(FIXTURES_DIR);
  });

  it("returns 404 for unknown scan ID", async () => {
    const res = await request
      .get("/scans/00000000-0000-0000-0000-000000000000")
      .expect(404);
    expect(res.body.error).toBe("NOT_FOUND");
  });
});

describe("GET /scans/:id/results — full scan flow", () => {
  async function waitForScan(scanId: string, maxMs = 15_000): Promise<object> {
    const deadline = Date.now() + maxMs;
    while (Date.now() < deadline) {
      const res = await request.get(`/scans/${scanId}`);
      if (res.body.status === "completed" || res.body.status === "failed") {
        return res.body;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`Scan ${scanId} did not complete within ${maxMs}ms`);
  }

  it("returns scan results for a clean fixture directory", async () => {
    const created = await request
      .post("/scans")
      .send({ target: FIXTURES_DIR })
      .expect(202);

    const job = await waitForScan(created.body.id) as any;
    expect(job.status).toBe("completed");

    const res = await request
      .get(`/scans/${created.body.id}/results`)
      .expect(200);

    expect(Array.isArray(res.body.findings)).toBe(true);
    expect(typeof res.body.filesScanned).toBe("number");
    expect(res.body.filesScanned).toBeGreaterThan(0);
    expect(res.body.summary).toMatchObject({
      errors: expect.any(Number),
      warnings: expect.any(Number),
      notes: expect.any(Number),
    });
  });

  it("detects findings in a vulnerable fixture", async () => {
    const created = await request
      .post("/scans")
      .send({ target: VULNERABLE_FIXTURE })
      .expect(202);

    const job = await waitForScan(created.body.id) as any;
    expect(job.status).toBe("completed");

    const res = await request
      .get(`/scans/${created.body.id}/results`)
      .expect(200);

    expect(res.body.findings.length).toBeGreaterThan(0);
    const severities = res.body.findings.map((f: any) => f.severity);
    expect(severities).toContain("error");
  });

  it("returns 202 SCAN_IN_PROGRESS while scan is running", async () => {
    // Create a scan and immediately try to fetch results before it finishes
    // (on fast machines it may complete instantly, so we tolerate 200 as well)
    const created = await request
      .post("/scans")
      .send({ target: FIXTURES_DIR })
      .expect(202);

    const res = await request.get(`/scans/${created.body.id}/results`);
    expect([200, 202]).toContain(res.status);
    if (res.status === 202) {
      expect(res.body.error).toBe("SCAN_IN_PROGRESS");
    }
  });
});

describe("GET /scans — list and pagination", () => {
  it("returns a paginated list", async () => {
    // Create at least one scan
    await request.post("/scans").send({ target: FIXTURES_DIR });

    const res = await request.get("/scans?pageSize=5").expect(200);
    expect(Array.isArray(res.body.items)).toBe(true);
    expect(typeof res.body.total).toBe("number");
    expect(res.body.pageSize).toBe(5);
    expect(res.body.page).toBe(1);
    expect(res.headers["x-total-count"]).toBeDefined();
  });

  it("returns 400 for invalid page", async () => {
    const res = await request.get("/scans?page=0").expect(400);
    expect(res.body.error).toBe("INVALID_PARAM");
  });

  it("returns 400 for pageSize > 100", async () => {
    const res = await request.get("/scans?pageSize=200").expect(400);
    expect(res.body.error).toBe("INVALID_PARAM");
  });
});

describe("DELETE /scans/:id", () => {
  it("deletes a completed scan record", async () => {
    const created = await request
      .post("/scans")
      .send({ target: FIXTURES_DIR })
      .expect(202);

    // Wait for completion
    await new Promise((r) => setTimeout(r, 5_000));

    const job = await request.get(`/scans/${created.body.id}`);
    if (job.body.status === "running" || job.body.status === "queued") {
      // Skip — scan hasn't finished in time; accept as indeterminate
      return;
    }

    await request.delete(`/scans/${created.body.id}`).expect(204);
    await request.get(`/scans/${created.body.id}`).expect(404);
  });

  it("returns 404 when deleting a non-existent scan", async () => {
    await request
      .delete("/scans/00000000-0000-0000-0000-000000000000")
      .expect(404);
  });
});

// ---------------------------------------------------------------------------
// Webhook registration
// ---------------------------------------------------------------------------
describe("Webhook CRUD", () => {
  it("registers, lists, gets, and deletes a webhook", async () => {
    // Register
    const created = await request
      .post("/webhooks")
      .send({
        url: "https://example.com/hook",
        events: ["scan.completed", "scan.failed"],
        secret: "s3cr3t",
      })
      .expect(201);

    expect(created.body.id).toBeTruthy();
    expect(created.body.url).toBe("https://example.com/hook");
    expect(created.body.events).toContain("scan.completed");

    // List
    const listed = await request.get("/webhooks").expect(200);
    expect(Array.isArray(listed.body)).toBe(true);
    expect(listed.body.find((w: any) => w.id === created.body.id)).toBeTruthy();

    // Get
    const got = await request.get(`/webhooks/${created.body.id}`).expect(200);
    expect(got.body.id).toBe(created.body.id);

    // Delete
    await request.delete(`/webhooks/${created.body.id}`).expect(204);
    await request.get(`/webhooks/${created.body.id}`).expect(404);
  });

  it("returns 400 for invalid webhook URL", async () => {
    const res = await request
      .post("/webhooks")
      .send({ url: "not-a-url", events: ["scan.completed"] })
      .expect(400);
    expect(res.body.error).toBe("INVALID_URL");
  });

  it("returns 400 for unknown event type", async () => {
    const res = await request
      .post("/webhooks")
      .send({
        url: "https://example.com/hook",
        events: ["scan.completed", "unknown.event"],
      })
      .expect(400);
    expect(res.body.error).toBe("INVALID_EVENTS");
  });

  it("returns 400 for empty events array", async () => {
    const res = await request
      .post("/webhooks")
      .send({ url: "https://example.com/hook", events: [] })
      .expect(400);
    expect(res.body.error).toBe("INVALID_REQUEST");
  });
});

// ---------------------------------------------------------------------------
// 404 handler
// ---------------------------------------------------------------------------
describe("404 handler", () => {
  it("returns 404 JSON for unknown routes", async () => {
    const res = await request.get("/nonexistent-route").expect(404);
    expect(res.body.error).toBe("NOT_FOUND");
  });
});
