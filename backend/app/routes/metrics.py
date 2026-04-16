from fastapi import APIRouter, Depends, Request

from app.core.security import get_current_user
from app.schemas import DashboardSummary, IngestionHealthResponse

router = APIRouter(tags=["metrics"])


@router.get("/metrics/summary", response_model=DashboardSummary)
async def metrics_summary(request: Request, current_user = Depends(get_current_user)):
    summary = await request.app.state.monitoring_service.summary(request.app.state.database)
    return DashboardSummary(**summary)


@router.get("/metrics/ingestion-health", response_model=IngestionHealthResponse)
async def metrics_ingestion_health(request: Request, current_user = Depends(get_current_user)):
    report = await request.app.state.monitoring_service.ingestion_health(request.app.state.database)
    return IngestionHealthResponse(**report)
