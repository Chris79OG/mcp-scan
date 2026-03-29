"""mcp-scan-client — Python client for the mcp-scan REST API."""

from .client import McpScanClient, McpScanApiError
from .models import (
    Severity,
    Finding,
    FindingSummary,
    ScanResult,
    ScanJobStatus,
    ScanJob,
    WebhookEvent,
    WebhookConfig,
    CreateScanRequest,
    CreateWebhookRequest,
    PaginatedList,
)

__all__ = [
    "McpScanClient",
    "McpScanApiError",
    "Severity",
    "Finding",
    "FindingSummary",
    "ScanResult",
    "ScanJobStatus",
    "ScanJob",
    "WebhookEvent",
    "WebhookConfig",
    "CreateScanRequest",
    "CreateWebhookRequest",
    "PaginatedList",
]
