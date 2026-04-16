from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.schemas import TuningRuleRecord, TuningRuleRequest, TuningSummary

router = APIRouter(prefix="/tuning", tags=["tuning"])


async def _load_rules(database) -> list[dict]:
    cursor = database["tuning_rules"].find({}).sort("updated_at", -1)
    rules: list[dict] = []
    async for document in cursor:
        rules.append(document)
    return rules


async def _count_matching_events(database, rule: dict) -> int:
    total = 0
    async for log in database["logs"].find({}):
        scope = rule.get("rule_scope")
        match_value = str(rule.get("match_value") or "")
        if scope == "threat_type" and match_value in {str(log.get("event_kind") or ""), str(log.get("metadata", {}).get("threat_type") or "")}:  # noqa: E501
            total += 1
        elif scope == "source" and match_value == str(log.get("source") or ""):
            total += 1
        elif scope == "host" and match_value == str(log.get("host") or ""):
            total += 1
        elif scope == "user" and match_value == str(log.get("username") or ""):
            total += 1
        elif scope == "ip" and match_value in {str(log.get("src_ip") or ""), str(log.get("dest_ip") or "")}:
            total += 1
    return total


@router.get("", response_model=list[TuningRuleRecord])
async def list_tuning_rules(database = Depends(get_database), current_user = Depends(get_current_user)):
    rules = await _load_rules(database)
    return [TuningRuleRecord(**rule) for rule in rules]


@router.get("/summary", response_model=TuningSummary)
async def tuning_summary(database = Depends(get_database), current_user = Depends(get_current_user)):
    rules = await _load_rules(database)
    suppressed_events = 0
    whitelisted_events = 0
    threshold_rules = 0
    for rule in rules:
        matched = await _count_matching_events(database, rule)
        action = str(rule.get("action") or "")
        if action == "suppress":
            suppressed_events += matched
        elif action == "whitelist":
            whitelisted_events += matched
        elif action == "threshold":
            threshold_rules += 1
    enabled_rules = sum(1 for rule in rules if rule.get("enabled", True))
    return TuningSummary(
        total_rules=len(rules),
        enabled_rules=enabled_rules,
        suppressed_events=suppressed_events,
        whitelisted_events=whitelisted_events,
        threshold_rules=threshold_rules,
    )


@router.post("", response_model=TuningRuleRecord, dependencies=[Depends(require_roles("admin", "analyst"))])
async def create_tuning_rule(payload: TuningRuleRequest, database = Depends(get_database), current_user = Depends(get_current_user)):
    rule = {
        "id": str(uuid4()),
        "name": payload.name,
        "rule_scope": payload.rule_scope,
        "match_value": payload.match_value,
        "action": payload.action,
        "threshold": payload.threshold,
        "window_minutes": payload.window_minutes,
        "enabled": payload.enabled,
        "notes": payload.notes,
        "created_by": current_user["username"],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    await database["tuning_rules"].insert_one(rule)
    return TuningRuleRecord(**rule)


@router.patch("/{rule_id}", response_model=TuningRuleRecord, dependencies=[Depends(require_roles("admin", "analyst"))])
async def update_tuning_rule(rule_id: str, payload: TuningRuleRequest, database = Depends(get_database), current_user = Depends(get_current_user)):
    rule = await database["tuning_rules"].find_one({"id": rule_id})
    if not rule:
        raise HTTPException(status_code=404, detail="Tuning rule not found")
    updates = {
        "name": payload.name,
        "rule_scope": payload.rule_scope,
        "match_value": payload.match_value,
        "action": payload.action,
        "threshold": payload.threshold,
        "window_minutes": payload.window_minutes,
        "enabled": payload.enabled,
        "notes": payload.notes,
        "updated_at": datetime.now(timezone.utc),
    }
    await database["tuning_rules"].update_one({"id": rule_id}, {"$set": updates})
    updated = await database["tuning_rules"].find_one({"id": rule_id})
    if not updated:
        raise HTTPException(status_code=404, detail="Tuning rule not found")
    return TuningRuleRecord(**updated)
