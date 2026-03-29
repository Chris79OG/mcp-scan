"""Typed dataclasses mirroring the mcp-scan API schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class WebhookEvent(str, Enum):
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_CRITICAL_FINDING = "scan.critical_finding"


@dataclass
class Finding:
    rule_id: str
    message: str
    severity: Severity
    file_path: str
    line: Optional[int] = None
    column: Optional[int] = None
    snippet: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            rule_id=d["ruleId"],
            message=d["message"],
            severity=Severity(d["severity"]),
            file_path=d["filePath"],
            line=d.get("line"),
            column=d.get("column"),
            snippet=d.get("snippet"),
        )


@dataclass
class FindingSummary:
    errors: int
    warnings: int
    notes: int

    @classmethod
    def from_dict(cls, d: dict) -> "FindingSummary":
        return cls(errors=d["errors"], warnings=d["warnings"], notes=d["notes"])


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str
    findings: List[Finding]
    files_scanned: int
    errors: List[str]
    summary: FindingSummary

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        return cls(
            target=d["target"],
            started_at=d["startedAt"],
            finished_at=d["finishedAt"],
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            files_scanned=d["filesScanned"],
            errors=d.get("errors", []),
            summary=FindingSummary.from_dict(d["summary"]),
        )


@dataclass
class ScanJob:
    id: str
    target: str
    status: ScanJobStatus
    created_at: str
    rules: Optional[List[str]] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[ScanResult] = None
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "ScanJob":
        return cls(
            id=d["id"],
            target=d["target"],
            status=ScanJobStatus(d["status"]),
            created_at=d["createdAt"],
            rules=d.get("rules"),
            started_at=d.get("startedAt"),
            completed_at=d.get("completedAt"),
            result=ScanResult.from_dict(d["result"]) if d.get("result") else None,
            error=d.get("error"),
        )


@dataclass
class WebhookConfig:
    id: str
    url: str
    events: List[WebhookEvent]
    created_at: str
    secret: Optional[str] = None

    @classmethod
    def from_dict(cls, d: dict) -> "WebhookConfig":
        return cls(
            id=d["id"],
            url=d["url"],
            events=[WebhookEvent(e) for e in d["events"]],
            created_at=d["createdAt"],
            secret=d.get("secret"),
        )


@dataclass
class PaginatedList:
    items: list
    total: int
    page: int
    page_size: int

    @classmethod
    def from_dict(cls, d: dict, item_factory) -> "PaginatedList":
        return cls(
            items=[item_factory(i) for i in d.get("items", [])],
            total=d["total"],
            page=d["page"],
            page_size=d["pageSize"],
        )


@dataclass
class CreateScanRequest:
    target: str
    rules: Optional[List[str]] = None
    webhook_url: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {"target": self.target}
        if self.rules is not None:
            d["rules"] = self.rules
        if self.webhook_url is not None:
            d["webhookUrl"] = self.webhook_url
        return d


@dataclass
class CreateWebhookRequest:
    url: str
    events: List[WebhookEvent]
    secret: Optional[str] = None

    def to_dict(self) -> dict:
        d: dict = {
            "url": self.url,
            "events": [e.value for e in self.events],
        }
        if self.secret is not None:
            d["secret"] = self.secret
        return d
