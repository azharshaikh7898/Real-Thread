from fastapi import APIRouter, Depends, HTTPException, Request
from typing import Literal
from pydantic import BaseModel

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.schemas import ThreatRecord

router = APIRouter(prefix="/threats", tags=["threats"])


class Threat(BaseModel):
    ip: str
    threat_type: str
    severity: str


@router.post("/create")
async def create_threat(threat: Threat):
    return {
        "message": "Threat received",
        "data": threat
    }


@router.get("", response_model=list[ThreatRecord])
async def get_threats(limit: int = 50, database = Depends(get_database)):
    cursor = database["threats"].find({}).sort("created_at", -1).limit(min(limit, 200))
    return [ThreatRecord(**document) async for document in cursor]


@router.get("/intel/ip/{ip}")
async def get_ip_intel(ip: str, request: Request, current_user = Depends(get_current_user)):
    service = request.app.state.threat_intel_service
    return await service.enrich_ip(ip)


@router.get("/{threat_id}/intel")
async def get_threat_intel(
    threat_id: str,
    request: Request,
    database = Depends(get_database),
    current_user = Depends(get_current_user),
):
    threat = await database["threats"].find_one({"id": threat_id})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    evidence = threat.get("evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get("threat_intel"), dict):
        return evidence["threat_intel"]

    source_ip = threat.get("source_ip")
    if not source_ip:
        raise HTTPException(status_code=400, detail="Threat has no source IP for enrichment")

    service = request.app.state.threat_intel_service
    intel = await service.enrich_ip(str(source_ip))

    new_evidence = evidence if isinstance(evidence, dict) else {}
    new_evidence["threat_intel"] = intel
    await database["threats"].update_one({"id": threat_id}, {"$set": {"evidence": new_evidence}})
    return intel


@router.post("/{threat_id}/enrich", response_model=ThreatRecord)
async def enrich_threat(
    threat_id: str,
    request: Request,
    database = Depends(get_database),
    current_user = Depends(require_roles("admin", "analyst")),
):
    threat = await database["threats"].find_one({"id": threat_id})
    if not threat:
        raise HTTPException(status_code=404, detail="Threat not found")

    source_ip = threat.get("source_ip")
    if not source_ip:
        raise HTTPException(status_code=400, detail="Threat has no source IP for enrichment")

    service = request.app.state.threat_intel_service
    intel = await service.enrich_ip(str(source_ip))

    evidence = threat.get("evidence")
    new_evidence = evidence if isinstance(evidence, dict) else {}
    new_evidence["threat_intel"] = intel
    await database["threats"].update_one({"id": threat_id}, {"$set": {"evidence": new_evidence}})

    updated = await database["threats"].find_one({"id": threat_id})
    return ThreatRecord(**updated)


@router.patch("/{threat_id}/status", response_model=ThreatRecord)
async def update_threat_status(
    threat_id: str,
    status: Literal["open", "investigating", "closed"],
    database = Depends(get_database),
    current_user = Depends(require_roles("admin", "analyst")),
):
    await database["threats"].update_one({"id": threat_id}, {"$set": {"status": status}})
    updated = await database["threats"].find_one({"id": threat_id})
    return ThreatRecord(**updated)
