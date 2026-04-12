from fastapi import APIRouter, Depends

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.schemas import AlertRecord

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertRecord])
async def get_alerts(limit: int = 50, database = Depends(get_database), current_user = Depends(get_current_user)):
    cursor = database["alerts"].find({}).sort("created_at", -1).limit(min(limit, 200))
    return [AlertRecord(**document) async for document in cursor]


@router.patch("/{alert_id}/acknowledge", response_model=AlertRecord)
async def acknowledge_alert(alert_id: str, database = Depends(get_database), current_user = Depends(require_roles("admin", "analyst"))):
    await database["alerts"].update_one({"id": alert_id}, {"$set": {"acknowledged": True, "delivery_status": "sent"}})
    updated = await database["alerts"].find_one({"id": alert_id})
    return AlertRecord(**updated)
