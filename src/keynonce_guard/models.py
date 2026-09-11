from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class FindingStatus(StrEnum):
    STATIC_SUSPICION = "static_suspicion"
    DYNAMIC_CONFIRMED = "dynamic_confirmed"
    NEEDS_REVIEW = "needs_review"
    RETEST_PENDING = "retest_pending"
    FIXED = "fixed"
    NOT_FIXED = "not_fixed"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Location(BaseModel):
    path: str
    line: int = Field(ge=1)
    column: int = Field(ge=0)


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(default_factory=lambda: f"F-{uuid4().hex[:12]}")
    scan_id: str
    rule_id: str
    rule_version: str = "1.0.0"
    category: str
    cwe_id: str | None = None
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    location: Location
    evidence: dict[str, Any]
    recommendation: str


class ScanSummary(BaseModel):
    scan_id: str
    status: str
    file_count: int
    finding_count: int
    elapsed_ms: int
    analyzer_version: str


class EvidenceRecord(BaseModel):
    evidence_id: str = Field(default_factory=lambda: f"EV-{uuid4().hex[:12]}")
    run_id: str
    target_digest: str
    tool_id: str
    tool_version: str
    rule_id: str | None = None
    observed: dict[str, Any]
    parent_digest: str | None = None
    record_digest: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AgentAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    target_id: str
    arguments: dict[str, str] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=500)


class AIExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    summary: str
    observed_evidence: list[str]
    evidence_ids: list[str]
    risk_context: str
    recommendation: str
    limitations: str


class TelemetryEvent(BaseModel):
    """Secret-free event accepted by the metadata threat-hunting slice."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    operation: str = Field(pattern="^(encrypt|sign)$")
    algorithm: str = Field(min_length=1, max_length=80)
    key_fingerprint: str = Field(pattern="^hmac-sha256:[0-9a-f]{64}$")
    nonce_fingerprint: str = Field(pattern="^hmac-sha256:[0-9a-f]{64}$")
    source_id: str = Field(min_length=1, max_length=100)
