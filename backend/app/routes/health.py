from datetime import datetime, timezone

from fastapi import APIRouter, Request

router = APIRouter(tags=["health"])


@router.get("/health")
async def health(request: Request):
    database = request.app.state.database
    status = "operational"
    try:
        await database.command("ping")
    except Exception:
        status = "degraded"
    return {
        "status": status,
        "service": request.app.state.settings.app_name,
        "websocket_connections": request.app.state.websocket_manager.connection_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
