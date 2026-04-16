from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SeverityLevel = Literal["info", "low", "medium", "high", "critical"]


class AppModel(BaseModel):
    model_config = ConfigDict(extra="ignore")


class LoginRequest(AppModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8, max_length=128)


class TokenResponse(AppModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class LogIngestRequest(AppModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = Field(default="system", max_length=32)
    host: str = Field(min_length=1, max_length=128)
    event_type: str = Field(min_length=1, max_length=64)
    message: str = Field(min_length=1, max_length=4096)
    severity: SeverityLevel = "info"
    status_code: int | None = Field(default=None, ge=100, le=599)
    username: str | None = Field(default=None, max_length=128)
    src_ip: str | None = Field(default=None, max_length=64)
    dest_ip: str | None = Field(default=None, max_length=64)
    process: str | None = Field(default=None, max_length=256)
    event_id: str | None = Field(default=None, max_length=64)
    action: str | None = Field(default=None, max_length=64)
    status: str | None = Field(default=None, max_length=64)
    user_agent: str | None = Field(default=None, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogRecord(LogIngestRequest):
    id: str
    received_at: datetime
    detected_threats: list[str] = Field(default_factory=list)
    schema_version: str = "1.0"
    normalized: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] = Field(default_factory=dict)
    parse_success: bool = True
    time_skew_seconds: float = 0.0


class LogIngestResponse(AppModel):
    message: str
    log: LogRecord
    threats: list["ThreatRecord"]


class ThreatRecord(AppModel):
    id: str
    log_id: str
    threat_type: str
    title: str
    description: str
    severity: SeverityLevel
    source_ip: str | None = None
    username: str | None = None
    confidence: float = Field(ge=0, le=1)
    created_at: datetime
    status: Literal["open", "investigating", "closed"] = "open"
    evidence: dict[str, Any] = Field(default_factory=dict)
    rule_id: str = "GEN-000"
    rule_version: str = "1.0"
    mitre_tactic: str = "Unknown"
    mitre_technique: str = "Unknown"
    response_guidance: str = "Investigate related telemetry and validate scope."


class AlertRecord(AppModel):
    id: str
    threat_id: str
    title: str
    message: str
    severity: SeverityLevel
    channel: str
    delivery_status: Literal["pending", "sent", "failed"] = "pending"
    acknowledged: bool = False
    created_at: datetime


class DashboardSummary(AppModel):
    total_logs: int
    total_threats: int
    open_alerts: int
    high_severity_threats: int
    system_status: str


class SourceHealthMetric(AppModel):
    source: str
    total_events: int
    parse_success_rate: float = Field(ge=0, le=100)
    field_completeness_rate: float = Field(ge=0, le=100)
    timestamp_skew_violations: int
    last_seen: datetime | None = None


class IngestionHealthResponse(AppModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_sources: int
    total_events: int
    source_metrics: list[SourceHealthMetric] = Field(default_factory=list)


class SourceOnboardRequest(AppModel):
    source_type: Literal["windows", "linux", "web", "network", "identity", "cloud", "generic"]
    sample_event: dict[str, Any]
    source_name: str | None = Field(default=None, max_length=128)


class SourceValidationResult(AppModel):
    source_type: str
    parse_success: bool
    normalized_event: dict[str, Any]
    enrichment: dict[str, Any]
    missing_fields: list[str] = Field(default_factory=list)
    validation_notes: list[str] = Field(default_factory=list)


class SourceOnboardRecord(AppModel):
    id: str
    source_type: str
    source_name: str | None = None
    sample_event: dict[str, Any]
    validation: SourceValidationResult
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TuningRuleRequest(AppModel):
    name: str = Field(min_length=3, max_length=128)
    rule_scope: Literal["threat_type", "source", "host", "user", "ip"]
    match_value: str = Field(min_length=1, max_length=256)
    action: Literal["whitelist", "suppress", "threshold"]
    threshold: int | None = Field(default=None, ge=1, le=1000)
    window_minutes: int | None = Field(default=None, ge=1, le=1440)
    enabled: bool = True
    notes: str | None = Field(default=None, max_length=2048)


class TuningRuleRecord(AppModel):
    id: str
    name: str
    rule_scope: str
    match_value: str
    action: str
    threshold: int | None = None
    window_minutes: int | None = None
    enabled: bool = True
    notes: str | None = None
    created_by: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TuningSummary(AppModel):
    total_rules: int
    enabled_rules: int
    suppressed_events: int
    whitelisted_events: int
    threshold_rules: int


class ReportSection(AppModel):
    title: str
    content: dict[str, Any]


class ReportArtifact(AppModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    executive_summary: dict[str, Any]
    architecture: dict[str, Any]
    detection_catalog: list[dict[str, Any]]
    dashboards: list[dict[str, Any]]
    triage_workflow: dict[str, Any]
    tuning: dict[str, Any]
    roadmap: list[str]


CaseDisposition = Literal["open", "true_positive", "false_positive", "benign_positive", "closed"]
CaseStatus = Literal["open", "investigating", "closed"]


class CaseCreateRequest(AppModel):
    alert_id: str | None = None
    threat_id: str | None = None
    title: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=4096)
    timeline_window_minutes: int = Field(default=60, ge=15, le=1440)


class CaseUpdateRequest(AppModel):
    title: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=4096)
    disposition: CaseDisposition | None = None
    status: CaseStatus | None = None
    evidence: list[dict[str, Any]] | None = None


class CaseTimelineEvent(AppModel):
    timestamp: datetime
    event_type: str
    source: str
    summary: str
    severity: SeverityLevel | str = "info"
    record_id: str | None = None
    entity: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CaseRecord(AppModel):
    id: str
    title: str
    description: str
    status: CaseStatus = "open"
    disposition: CaseDisposition = "open"
    owner: str | None = None
    notes: str = ""
    created_by: str
    alert_id: str | None = None
    threat_id: str | None = None
    source_ip: str | None = None
    username: str | None = None
    host: str | None = None
    observed_at: datetime | None = None
    rule_id: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    severity: SeverityLevel | str = "info"
    timeline_window_minutes: int = 60
    impacted_entities: list[dict[str, Any]] = Field(default_factory=list)
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    related_log_ids: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    related_threat_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class LiveEvent(AppModel):
    event_type: Literal["log", "threat", "alert", "status"]
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserProfile(AppModel):
    id: str
    username: str
    role: Literal["admin", "analyst"]
    is_active: bool = True
