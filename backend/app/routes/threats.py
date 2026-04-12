from fastapi import APIRouter, Depends
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
