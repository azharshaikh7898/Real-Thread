from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.schemas import CaseCreateRequest, CaseRecord, CaseTimelineEvent, CaseUpdateRequest

router = APIRouter(prefix="/cases", tags=["cases"])


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        return datetime.fromisoformat(value)
    return datetime.now(timezone.utc)


def _entity_matches(case: dict[str, Any], document: dict[str, Any]) -> bool:
    for field in ("source_ip", "username", "host"):
        case_value = case.get(field)
        if case_value and document.get(field) == case_value:
            return True
    return False


async def build_case_timeline(database, case: dict[str, Any]) -> list[dict[str, Any]]:
    anchor_time = _coerce_datetime(case.get("observed_at") or case.get("created_at"))
    window_minutes = int(case.get("timeline_window_minutes") or 60)
    start_time = anchor_time - timedelta(minutes=window_minutes)
    end_time = anchor_time + timedelta(minutes=window_minutes)
    timeline: list[dict[str, Any]] = [
        {
            "timestamp": anchor_time,
            "event_type": "case",
            "source": "case-management",
            "summary": f'Case "{case["title"]}" opened for investigation',
            "severity": case.get("severity", "info"),
            "record_id": case["id"],
            "entity": case.get("source_ip") or case.get("username") or case.get("host"),
            "metadata": {
                "status": case.get("status"),
                "disposition": case.get("disposition"),
                "owner": case.get("owner"),
            },
        }
    ]

    async for log in database["logs"].find({}):
        timestamp = _coerce_datetime(log.get("timestamp") or log.get("received_at"))
        if not (start_time <= timestamp <= end_time):
            continue
        if not _entity_matches(case, log):
            continue
        timeline.append(
            {
                "timestamp": timestamp,
                "event_type": "log",
                "source": str(log.get("source") or "system"),
                "summary": log.get("message", "Log event"),
                "severity": log.get("severity", "info"),
                "record_id": log.get("id"),
                "entity": log.get("src_ip") or log.get("username") or log.get("host"),
                "metadata": {
                    "event_type": log.get("event_type"),
                    "event_kind": log.get("event_kind"),
                    "status_code": log.get("status_code"),
                    "detected_threats": log.get("detected_threats", []),
                },
            }
        )

    async for threat in database["threats"].find({}):
        timestamp = _coerce_datetime(threat.get("created_at"))
        if not (start_time <= timestamp <= end_time):
            continue
        if not _entity_matches(case, threat):
            continue
        timeline.append(
            {
                "timestamp": timestamp,
                "event_type": "threat",
                "source": "detection-engine",
                "summary": threat.get("title", threat.get("threat_type", "Threat")),
                "severity": threat.get("severity", "info"),
                "record_id": threat.get("id"),
                "entity": threat.get("source_ip") or threat.get("username"),
                "metadata": {
                    "threat_type": threat.get("threat_type"),
                    "rule_id": threat.get("rule_id"),
                    "mitre_tactic": threat.get("mitre_tactic"),
                    "mitre_technique": threat.get("mitre_technique"),
                    "status": threat.get("status"),
                },
            }
        )

    async for alert in database["alerts"].find({}):
        timestamp = _coerce_datetime(alert.get("created_at"))
        if not (start_time <= timestamp <= end_time):
            continue
        related_threat = None
        if alert.get("threat_id"):
            related_threat = await database["threats"].find_one({"id": alert["threat_id"]})
        if related_threat and not _entity_matches(case, related_threat):
            continue
        if related_threat is None and not _entity_matches(case, alert):
            continue
        timeline.append(
            {
                "timestamp": timestamp,
                "event_type": "alert",
                "source": "alerting",
                "summary": alert.get("title", "Alert"),
                "severity": alert.get("severity", "info"),
                "record_id": alert.get("id"),
                "entity": case.get("source_ip") or case.get("username") or case.get("host"),
                "metadata": {
                    "delivery_status": alert.get("delivery_status"),
                    "acknowledged": alert.get("acknowledged", False),
                    "threat_id": alert.get("threat_id"),
                },
            }
        )

    timeline.sort(key=lambda item: item["timestamp"])
    return timeline


async def _build_case_document(database, payload: CaseCreateRequest, actor: dict[str, Any]) -> dict[str, Any]:
    alert = None
    threat = None
    log = None

    if not payload.alert_id and not payload.threat_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="alert_id or threat_id is required")

    if payload.alert_id:
        alert = await database["alerts"].find_one({"id": payload.alert_id})
        if not alert:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
        threat = await database["threats"].find_one({"id": alert["threat_id"]}) if alert.get("threat_id") else None

    if payload.threat_id:
        threat = await database["threats"].find_one({"id": payload.threat_id})
        if not threat:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat not found")
        if not alert:
            alert = await database["alerts"].find_one({"threat_id": threat["id"]})

    if threat and threat.get("log_id"):
        log = await database["logs"].find_one({"id": threat["log_id"]})

    source_ip = (threat or {}).get("source_ip") or (log or {}).get("src_ip")
    username = (threat or {}).get("username") or (log or {}).get("username")
    host = (log or {}).get("host")
    observed_at = _coerce_datetime((alert or {}).get("created_at") or (threat or {}).get("created_at") or (log or {}).get("timestamp") or datetime.now(timezone.utc))

    title = payload.title or (threat or {}).get("title") or (alert or {}).get("title") or "Investigation case"
    description = payload.description or (threat or {}).get("description") or (alert or {}).get("message") or "SOC investigation case"
    severity = (threat or {}).get("severity") or (alert or {}).get("severity") or "info"

    impacted_entities = []
    if source_ip:
        impacted_entities.append({"type": "ip", "value": source_ip, "role": "suspected_source"})
    if username:
        impacted_entities.append({"type": "user", "value": username, "role": "suspected_account"})
    if host:
        impacted_entities.append({"type": "host", "value": host, "role": "impacted_asset"})

    return {
        "id": str(uuid4()),
        "title": title,
        "description": description,
        "status": "open",
        "disposition": "open",
        "owner": payload.owner,
        "notes": payload.notes or "",
        "created_by": actor["username"],
        "alert_id": (alert or {}).get("id"),
        "threat_id": (threat or {}).get("id"),
        "source_ip": source_ip,
        "username": username,
        "host": host,
        "observed_at": observed_at,
        "rule_id": (threat or {}).get("rule_id"),
        "mitre_tactic": (threat or {}).get("mitre_tactic"),
        "mitre_technique": (threat or {}).get("mitre_technique"),
        "severity": severity,
        "timeline_window_minutes": payload.timeline_window_minutes,
        "impacted_entities": impacted_entities,
        "evidence": [],
        "related_log_ids": [log["id"]] if log else [],
        "related_alert_ids": [(alert or {}).get("id")] if alert else [],
        "related_threat_ids": [(threat or {}).get("id")] if threat else [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


@router.get("", response_model=list[CaseRecord])
async def list_cases(limit: int = 25, database = Depends(get_database), current_user = Depends(get_current_user)):
    cursor = database["cases"].find({}).sort("updated_at", -1).limit(min(limit, 100))
    return [CaseRecord(**document) async for document in cursor]


@router.post("", response_model=CaseRecord)
async def create_case(
    payload: CaseCreateRequest,
    request: Request,
    database = Depends(get_database),
    current_user = Depends(require_roles("admin", "analyst")),
):
    case = await _build_case_document(database, payload, current_user)
    await database["cases"].insert_one(case)
    return CaseRecord(**case)


@router.get("/{case_id}", response_model=CaseRecord)
async def get_case(case_id: str, database = Depends(get_database), current_user = Depends(get_current_user)):
    case = await database["cases"].find_one({"id": case_id})
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return CaseRecord(**case)


@router.get("/{case_id}/timeline", response_model=list[CaseTimelineEvent])
async def get_case_timeline(case_id: str, database = Depends(get_database), current_user = Depends(get_current_user)):
    case = await database["cases"].find_one({"id": case_id})
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    timeline = await build_case_timeline(database, case)
    return [CaseTimelineEvent(**event) for event in timeline]


@router.patch("/{case_id}", response_model=CaseRecord)
async def update_case(
    case_id: str,
    payload: CaseUpdateRequest,
    database = Depends(get_database),
    current_user = Depends(require_roles("admin", "analyst")),
):
    case = await database["cases"].find_one({"id": case_id})
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    updates: dict[str, Any] = {"updated_at": datetime.now(timezone.utc)}
    if payload.title is not None:
        updates["title"] = payload.title
    if payload.description is not None:
        updates["description"] = payload.description
    if payload.owner is not None:
        updates["owner"] = payload.owner
    if payload.notes is not None:
        updates["notes"] = payload.notes
    if payload.disposition is not None:
        updates["disposition"] = payload.disposition
    if payload.status is not None:
        updates["status"] = payload.status
    if payload.evidence is not None:
        updates["evidence"] = payload.evidence

    await database["cases"].update_one({"id": case_id}, {"$set": updates})
    updated = await database["cases"].find_one({"id": case_id})
    if not updated:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return CaseRecord(**updated)
