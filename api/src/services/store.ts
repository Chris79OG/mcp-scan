import { ScanJob } from "../types";

/**
 * In-memory scan job store.
 *
 * For production use, swap this implementation with a persistent backend
 * (e.g., Redis, PostgreSQL) while keeping the same interface.
 */
export class ScanJobStore {
  private jobs: Map<string, ScanJob> = new Map();

  /** Store a new job. Overwrites if same ID exists. */
  set(job: ScanJob): void {
    this.jobs.set(job.id, { ...job });
  }

  /** Retrieve a job by ID. Returns undefined if not found. */
  get(id: string): ScanJob | undefined {
    const job = this.jobs.get(id);
    return job ? { ...job } : undefined;
  }

  /** List jobs with optional pagination and status filter. */
  list(opts: {
    page?: number;
    pageSize?: number;
    status?: ScanJob["status"];
  } = {}): { items: ScanJob[]; total: number } {
    const page = Math.max(1, opts.page ?? 1);
    const pageSize = Math.min(100, Math.max(1, opts.pageSize ?? 20));

    let all = Array.from(this.jobs.values()).sort(
      (a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );

    if (opts.status) {
      all = all.filter((j) => j.status === opts.status);
    }

    const total = all.length;
    const items = all.slice((page - 1) * pageSize, page * pageSize).map((j) => ({ ...j }));
    return { items, total };
  }

  /** Update a job partially. */
  update(id: string, patch: Partial<ScanJob>): ScanJob | undefined {
    const existing = this.jobs.get(id);
    if (!existing) return undefined;
    const updated = { ...existing, ...patch };
    this.jobs.set(id, updated);
    return { ...updated };
  }

  /** Delete a job. Returns true if it existed. */
  delete(id: string): boolean {
    return this.jobs.delete(id);
  }

  /** Number of jobs in the store. */
  get size(): number {
    return this.jobs.size;
  }
}

/** Singleton store instance shared across the API server process. */
export const store = new ScanJobStore();
