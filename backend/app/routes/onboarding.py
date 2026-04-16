from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, Request

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.schemas import SourceOnboardRecord, SourceOnboardRequest, SourceValidationResult

router = APIRouter(prefix="/onboarding", tags=["onboarding"])

_REQUIRED_FIELDS = {
    "windows": ["host", "event_id", "message", "username"],
    "linux": ["host", "message", "username"],
    "web": ["host", "message", "src_ip", "status_code"],
    "network": ["host", "message", "src_ip", "dest_ip"],
    "identity": ["host", "message", "username"],
    "cloud": ["host", "message", "event_id"],
    "generic": ["host", "message"],
}

_SUPPORTED_SOURCES = [
    {"source_type": "windows", "description": "Windows Security/System logs"},
    {"source_type": "linux", "description": "Linux auth and syslog events"},
    {"source_type": "web", "description": "Nginx/Apache access logs"},
    {"source_type": "network", "description": "Firewall/VPN/router logs"},
    {"source_type": "identity", "description": "Identity and sign-in telemetry"},
    {"source_type": "cloud", "description": "Cloud activity telemetry"},
    {"source_type": "generic", "description": "Generic structured telemetry"},
]


def _validate_sample(source_type: str, sample_event: dict) -> SourceValidationResult:
    service_required = _REQUIRED_FIELDS.get(source_type, _REQUIRED_FIELDS["generic"])
    missing_fields = [field for field in service_required if not sample_event.get(field)]
    notes = []
    if missing_fields:
        notes.append(f"Missing recommended fields: {', '.join(missing_fields)}")
    else:
        notes.append("All recommended fields present")

    normalized = {
        "source": source_type,
        "host": sample_event.get("host"),
        "event_type": sample_event.get("event_type") or source_type,
        "message": sample_event.get("message"),
        "src_ip": sample_event.get("src_ip"),
        "dest_ip": sample_event.get("dest_ip"),
        "username": sample_event.get("username"),
        "status_code": sample_event.get("status_code"),
        "event_id": sample_event.get("event_id"),
        "action": sample_event.get("action"),
        "process": sample_event.get("process"),
    }
    enrichment = {
        "asset_criticality": "high" if any(token in str(sample_event.get("host", "")).lower() for token in ("srv", "prod", "dc", "db")) else "medium",
        "user_role": "admin" if any(token in str(sample_event.get("username", "")).lower() for token in ("admin", "root", "svc")) else "user",
        "ioc_match": False,
        "ioc_indicator": None,
    }
    return SourceValidationResult(
        source_type=source_type,
        parse_success=len(missing_fields) == 0,
        normalized_event=normalized,
        enrichment=enrichment,
        missing_fields=missing_fields,
        validation_notes=notes,
    )


@router.get("/supported", dependencies=[Depends(get_current_user)])
async def supported_sources():
    return {"sources": _SUPPORTED_SOURCES}


@router.post("/validate", response_model=SourceValidationResult, dependencies=[Depends(require_roles("admin", "analyst"))])
async def validate_source(payload: SourceOnboardRequest):
    return _validate_sample(payload.source_type, payload.sample_event)


@router.post("/register", response_model=SourceOnboardRecord, dependencies=[Depends(require_roles("admin", "analyst"))])
async def register_source(payload: SourceOnboardRequest, request: Request, database = Depends(get_database)):
    validation = _validate_sample(payload.source_type, payload.sample_event)
    record = {
        "id": str(uuid4()),
        "source_type": payload.source_type,
        "source_name": payload.source_name,
        "sample_event": payload.sample_event,
        "validation": validation.model_dump(),
        "created_at": datetime.now(timezone.utc),
    }
    await database["onboarding_sources"].insert_one(record)
    return SourceOnboardRecord(**record)


@router.get("/sources", dependencies=[Depends(get_current_user)])
async def list_registered_sources(database = Depends(get_database)):
    cursor = database["onboarding_sources"].find({}).sort("created_at", -1)
    items = []
    async for document in cursor:
        items.append(SourceOnboardRecord(**document))
    return items
