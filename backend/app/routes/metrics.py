from fastapi import APIRouter, Depends, Request

from app.core.security import get_current_user
from app.schemas import DashboardSummary

router = APIRouter(tags=["metrics"])


@router.get("/metrics/summary", response_model=DashboardSummary)
async def metrics_summary(request: Request, current_user = Depends(get_current_user)):
    summary = await request.app.state.monitoring_service.summary(request.app.state.database)
    return DashboardSummary(**summary)
