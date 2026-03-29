# mcp-scan Deployment Runbook

## Overview

mcp-scan runs as a Docker container exposing:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe — returns `{"status":"ok","uptime":<ms>}` |
| `GET /metrics` | Prometheus-compatible plaintext metrics |
| `POST /scan` | Submit a scan request — body: `{"input":"<path>","rules":[...]}` |

The container also ships the CLI (`dist/cli.js`) for one-shot scans.

---

## Prerequisites

- Docker ≥ 24 and Docker Compose v2 on the target host
- GitHub Container Registry access (image: `ghcr.io/syntrophy/mcp-scan`)
- SSH access to the staging/production server
- Secrets configured in GitHub → Settings → Environments:
  - `STAGING_HOST` — hostname/IP of staging server
  - `STAGING_USER` — SSH user (should have docker permissions)
  - `STAGING_SSH_KEY` — private key for SSH login
  - `NPM_TOKEN` — for npm publish (publish workflow only)

---

## First-time Server Setup

```bash
# On the staging/production host:
sudo mkdir -p /opt/mcp-scan/scans
sudo cp deploy/staging.env.example /opt/mcp-scan/staging.env
# Edit /opt/mcp-scan/staging.env with real values

sudo cp docker-compose.staging.yml /opt/mcp-scan/docker-compose.staging.yml

# Log in to GHCR (one-time)
echo "<GITHUB_PAT>" | docker login ghcr.io -u <github-username> --password-stdin

# Initial start
cd /opt/mcp-scan
docker compose -f docker-compose.staging.yml up -d
```

---

## Manual Deployment

Use this when you need to deploy outside of CI (e.g. hotfix, roll forward).

```bash
# SSH into the staging host
ssh deploy@<STAGING_HOST>

cd /opt/mcp-scan

# Pull the image you want to deploy
docker pull ghcr.io/syntrophy/mcp-scan:latest   # or a specific sha- tag

# Restart with the new image
docker compose -f docker-compose.staging.yml up -d --remove-orphans

# Confirm health
curl -s http://localhost:3000/health
# Expected: {"status":"ok","uptime":...}
```

---

## Rollback Procedure

1. Identify the last known good image tag from the GitHub Actions run history (look for `sha-<commit>` tags).

2. Update the image reference in `docker-compose.staging.yml`:
   ```yaml
   image: ghcr.io/syntrophy/mcp-scan:sha-<good-commit>
   ```

3. Apply the rollback:
   ```bash
   cd /opt/mcp-scan
   docker compose -f docker-compose.staging.yml up -d
   curl -s http://localhost:3000/health
   ```

4. Open an incident issue and tag the team.

---

## Health Verification

After every deployment, verify these pass:

```bash
# 1. Liveness
curl -sf http://<HOST>:3000/health | jq .
# {"status":"ok","uptime":1234}

# 2. Metrics
curl -sf http://<HOST>:3000/metrics
# mcp_scan_total 0
# ...

# 3. Smoke scan (container must have /scans mounted with a sample dir)
curl -sf -X POST http://<HOST>:3000/scan \
  -H 'Content-Type: application/json' \
  -d '{"input":"/scans/sample"}' | jq '.summary'
```

---

## Monitoring & Alerting

Metrics are available in Prometheus format at `/metrics`. Key signals:

| Metric | Alert threshold |
|---|---|
| `mcp_scan_errors_total` rate | > 5/min → warning |
| `mcp_scan_avg_latency_ms` | > 10 000 ms → warning |
| Container `unhealthy` state | Immediate page |

To scrape metrics with Prometheus, add to `prometheus.yml`:

```yaml
- job_name: mcp-scan
  static_configs:
    - targets: ['<HOST>:3000']
  metrics_path: /metrics
```

Docker restart policy (`restart: always` in staging compose) auto-recovers from crashes.

---

## Incident Response

1. **Check health**: `curl http://<HOST>:3000/health`
2. **Check logs**: `docker compose -f docker-compose.staging.yml logs --tail=100 mcp-scan`
3. **Check metrics**: `curl http://<HOST>:3000/metrics`
4. **If container is down**: `docker compose -f docker-compose.staging.yml up -d`
5. **If problem persists**: rollback (see above) and escalate.

---

## One-shot CLI scan (without server)

```bash
# Run a scan directly in the container, no server mode
docker run --rm \
  -v /path/to/mcp-server:/workspace:ro \
  ghcr.io/syntrophy/mcp-scan:latest \
  node dist/cli.js --input /workspace --output sarif > results.sarif.json
```

---

## Production Promotion

Production uses the same image as staging (immutable tags). To promote:

1. Verify staging is healthy with the target image tag.
2. Update `/opt/mcp-scan/docker-compose.yml` on the production host to use that tag.
3. Apply and verify health.
4. Tag the commit as a release: `git tag v<version> && git push --tags`
   — this triggers the publish workflow which also creates a versioned Docker tag.
