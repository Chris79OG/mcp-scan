"""Synchronous and async Python clients for the mcp-scan API."""

from __future__ import annotations

import time
from typing import List, Optional

import httpx

from .models import (
    ScanJob,
    ScanResult,
    WebhookConfig,
    PaginatedList,
    CreateScanRequest,
    CreateWebhookRequest,
    ScanJobStatus,
)


class McpScanApiError(Exception):
    """Raised when the mcp-scan API returns a non-2xx response."""

    def __init__(self, status_code: int, error_code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code

    def __repr__(self) -> str:
        return f"McpScanApiError(status={self.status_code}, error={self.error_code!r})"


def _raise_for_status(response: httpx.Response) -> None:
    if response.is_error:
        try:
            body = response.json()
            raise McpScanApiError(
                status_code=response.status_code,
                error_code=body.get("error", "UNKNOWN_ERROR"),
                message=body.get("message", f"HTTP {response.status_code}"),
            )
        except (ValueError, KeyError):
            raise McpScanApiError(
                status_code=response.status_code,
                error_code="UNKNOWN_ERROR",
                message=f"HTTP {response.status_code}",
            )


class McpScanClient:
    """
    Synchronous client for the mcp-scan REST API.

    Example::

        from mcp_scan_client import McpScanClient, CreateScanRequest

        client = McpScanClient(base_url="http://localhost:3001")

        # Trigger a scan
        job = client.scans.create(CreateScanRequest(target="/path/to/mcp-server"))

        # Poll until complete
        result = client.scans.wait_for_result(job.id)
        print(f"Found {result.summary.errors} error(s)")
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )
        self.scans = _ScansClient(self._http)
        self.webhooks = _WebhooksClient(self._http)

    def health(self) -> dict:
        """Check server health."""
        res = self._http.get("/health")
        _raise_for_status(res)
        return res.json()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "McpScanClient":
        return self

    def __exit__(self, *args) -> None:
        self.close()


class _ScansClient:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(self, req: CreateScanRequest) -> ScanJob:
        """Initiate a new scan job."""
        res = self._http.post("/scans", json=req.to_dict())
        _raise_for_status(res)
        return ScanJob.from_dict(res.json())

    def list(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[ScanJobStatus] = None,
    ) -> PaginatedList:
        """List scan history."""
        params: dict = {"page": page, "pageSize": page_size}
        if status is not None:
            params["status"] = status.value
        res = self._http.get("/scans", params=params)
        _raise_for_status(res)
        return PaginatedList.from_dict(res.json(), ScanJob.from_dict)

    def get(self, scan_id: str) -> ScanJob:
        """Get the current state of a scan job."""
        res = self._http.get(f"/scans/{scan_id}")
        _raise_for_status(res)
        return ScanJob.from_dict(res.json())

    def get_results(self, scan_id: str) -> ScanResult:
        """Retrieve full results for a completed scan."""
        res = self._http.get(f"/scans/{scan_id}/results")
        _raise_for_status(res)
        return ScanResult.from_dict(res.json())

    def delete(self, scan_id: str) -> None:
        """Delete a scan record."""
        res = self._http.delete(f"/scans/{scan_id}")
        _raise_for_status(res)

    def wait_for_result(
        self,
        scan_id: str,
        interval_seconds: float = 2.0,
        max_wait_seconds: float = 300.0,
    ) -> ScanResult:
        """
        Poll until the scan completes, then return the results.

        :raises McpScanApiError: if the scan fails
        :raises TimeoutError: if the scan doesn't complete within max_wait_seconds
        """
        deadline = time.monotonic() + max_wait_seconds
        while time.monotonic() < deadline:
            job = self.get(scan_id)
            if job.status == ScanJobStatus.COMPLETED:
                return self.get_results(scan_id)
            if job.status == ScanJobStatus.FAILED:
                raise McpScanApiError(
                    status_code=422,
                    error_code="SCAN_FAILED",
                    message=f"Scan {scan_id} failed: {job.error or 'unknown error'}",
                )
            time.sleep(interval_seconds)
        raise TimeoutError(
            f"Timed out waiting for scan {scan_id} after {max_wait_seconds}s"
        )


class _WebhooksClient:
    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def create(self, req: CreateWebhookRequest) -> WebhookConfig:
        """Register a new webhook."""
        res = self._http.post("/webhooks", json=req.to_dict())
        _raise_for_status(res)
        return WebhookConfig.from_dict(res.json())

    def list(self) -> List[WebhookConfig]:
        """List all registered webhooks."""
        res = self._http.get("/webhooks")
        _raise_for_status(res)
        return [WebhookConfig.from_dict(w) for w in res.json()]

    def get(self, webhook_id: str) -> WebhookConfig:
        """Get a webhook by ID."""
        res = self._http.get(f"/webhooks/{webhook_id}")
        _raise_for_status(res)
        return WebhookConfig.from_dict(res.json())

    def delete(self, webhook_id: str) -> None:
        """Unregister a webhook."""
        res = self._http.delete(f"/webhooks/{webhook_id}")
        _raise_for_status(res)


# ---------------------------------------------------------------------------
# Async client (requires httpx[asyncio])
# ---------------------------------------------------------------------------

class AsyncMcpScanClient:
    """
    Async client for the mcp-scan REST API (requires Python 3.9+).

    Example::

        import asyncio
        from mcp_scan_client import AsyncMcpScanClient, CreateScanRequest

        async def main():
            async with AsyncMcpScanClient(base_url="http://localhost:3001") as client:
                job = await client.scans.create(
                    CreateScanRequest(target="/path/to/mcp-server")
                )
                result = await client.scans.wait_for_result(job.id)
                print(f"Found {result.summary.errors} error(s)")

        asyncio.run(main())
    """

    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )
        self.scans = _AsyncScansClient(self._http)
        self.webhooks = _AsyncWebhooksClient(self._http)

    async def health(self) -> dict:
        res = await self._http.get("/health")
        _raise_for_status(res)
        return res.json()

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncMcpScanClient":
        return self

    async def __aexit__(self, *args) -> None:
        await self.aclose()


class _AsyncScansClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(self, req: CreateScanRequest) -> ScanJob:
        res = await self._http.post("/scans", json=req.to_dict())
        _raise_for_status(res)
        return ScanJob.from_dict(res.json())

    async def list(
        self,
        page: int = 1,
        page_size: int = 20,
        status: Optional[ScanJobStatus] = None,
    ) -> PaginatedList:
        params: dict = {"page": page, "pageSize": page_size}
        if status is not None:
            params["status"] = status.value
        res = await self._http.get("/scans", params=params)
        _raise_for_status(res)
        return PaginatedList.from_dict(res.json(), ScanJob.from_dict)

    async def get(self, scan_id: str) -> ScanJob:
        res = await self._http.get(f"/scans/{scan_id}")
        _raise_for_status(res)
        return ScanJob.from_dict(res.json())

    async def get_results(self, scan_id: str) -> ScanResult:
        res = await self._http.get(f"/scans/{scan_id}/results")
        _raise_for_status(res)
        return ScanResult.from_dict(res.json())

    async def delete(self, scan_id: str) -> None:
        res = await self._http.delete(f"/scans/{scan_id}")
        _raise_for_status(res)

    async def wait_for_result(
        self,
        scan_id: str,
        interval_seconds: float = 2.0,
        max_wait_seconds: float = 300.0,
    ) -> ScanResult:
        import asyncio
        deadline = time.monotonic() + max_wait_seconds
        while time.monotonic() < deadline:
            job = await self.get(scan_id)
            if job.status == ScanJobStatus.COMPLETED:
                return await self.get_results(scan_id)
            if job.status == ScanJobStatus.FAILED:
                raise McpScanApiError(
                    status_code=422,
                    error_code="SCAN_FAILED",
                    message=f"Scan {scan_id} failed: {job.error or 'unknown error'}",
                )
            await asyncio.sleep(interval_seconds)
        raise TimeoutError(
            f"Timed out waiting for scan {scan_id} after {max_wait_seconds}s"
        )


class _AsyncWebhooksClient:
    def __init__(self, http: httpx.AsyncClient) -> None:
        self._http = http

    async def create(self, req: CreateWebhookRequest) -> WebhookConfig:
        res = await self._http.post("/webhooks", json=req.to_dict())
        _raise_for_status(res)
        return WebhookConfig.from_dict(res.json())

    async def list(self) -> List[WebhookConfig]:
        res = await self._http.get("/webhooks")
        _raise_for_status(res)
        return [WebhookConfig.from_dict(w) for w in res.json()]

    async def get(self, webhook_id: str) -> WebhookConfig:
        res = await self._http.get(f"/webhooks/{webhook_id}")
        _raise_for_status(res)
        return WebhookConfig.from_dict(res.json())

    async def delete(self, webhook_id: str) -> None:
        res = await self._http.delete(f"/webhooks/{webhook_id}")
        _raise_for_status(res)
