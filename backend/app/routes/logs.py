from fastapi import APIRouter, Depends, Request

from app.core.security import get_current_user, require_roles
from app.db import get_database
from app.dependencies import rate_limit_dependency
from app.schemas import LogIngestRequest, LogIngestResponse, LogRecord, ThreatRecord

router = APIRouter(tags=["logs"])


@router.post("/logs", response_model=LogIngestResponse, dependencies=[Depends(rate_limit_dependency("logs", 120, 60))])
async def ingest_log(
    payload: LogIngestRequest,
    request: Request,
    database = Depends(get_database),
    current_user = Depends(require_roles("admin", "analyst")),
):
    service = request.app.state.monitoring_service
    result = await service.ingest_log(database, payload.model_dump(), current_user)
    return LogIngestResponse(
        message="Log ingested successfully",
        log=LogRecord(**result["log"]),
        threats=[ThreatRecord(**threat) for threat in result["threats"]],
    )


@router.get("/logs/recent", response_model=list[LogRecord])
async def recent_logs(limit: int = 50, database = Depends(get_database), current_user = Depends(get_current_user)):
    cursor = database["logs"].find({}).sort("timestamp", -1).limit(min(limit, 200))
    return [LogRecord(**document) async for document in cursor]
