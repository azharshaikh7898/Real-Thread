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
    user_agent: str | None = Field(default=None, max_length=256)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LogRecord(LogIngestRequest):
    id: str
    received_at: datetime
    detected_threats: list[str] = Field(default_factory=list)


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


class LiveEvent(AppModel):
    event_type: Literal["log", "threat", "alert", "status"]
    payload: dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserProfile(AppModel):
    id: str
    username: str
    role: Literal["admin", "analyst"]
    is_active: bool = True
