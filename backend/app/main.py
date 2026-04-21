from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.rate_limiter import InMemoryRateLimiter
from app.core.security import hash_password
from app.local_db import LocalDatabase
from app.routes.alerts import router as alerts_router
from app.routes.cases import router as cases_router
from app.routes.auth import router as auth_router
from app.routes.health import router as health_router
from app.routes.onboarding import router as onboarding_router
from app.routes.logs import router as logs_router
from app.routes.metrics import router as metrics_router
from app.routes.reports import router as reports_router
from app.routes.threats import router as threats_router
from app.routes.tuning import router as tuning_router
from app.sample_data import SAMPLE_LOGS
from app.services.detector import ThreatDetector
from app.services.monitoring import MonitoringService
from app.services.notifier import Notifier
from app.services.threat_intel import ThreatIntelService
from app.services.websocket_manager import WebSocketManager


async def _wait_for_database(database) -> None:
    for attempt in range(30):
        try:
            await database.command("ping")
            return
        except Exception:
            if attempt == 29:
                raise
            await asyncio.sleep(1)


async def _seed_demo_data(app: FastAPI) -> None:
    database = app.state.database
    settings = app.state.settings

    if settings.seed_default_users and await database["users"].count_documents({}) == 0:
        await database["users"].insert_many(
            [
                {
                    "id": "user-admin",
                    "username": "admin",
                    "password_hash": hash_password("ChangeMe123!"),
                    "role": "admin",
                    "is_active": True,
                },
                {
                    "id": "user-analyst",
                    "username": "analyst",
                    "password_hash": hash_password("ChangeMe123!"),
                    "role": "analyst",
                    "is_active": True,
                },
            ]
        )

    if settings.seed_demo_logs and await database["logs"].count_documents({}) == 0:
        actor = {"id": "user-admin", "username": "admin", "role": "admin"}
        for payload in SAMPLE_LOGS:
            await app.state.monitoring_service.ingest_log(database, payload, actor)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    database = LocalDatabase(settings.database_path)

    app.state.settings = settings
    app.state.database = database
    app.state.rate_limiter = InMemoryRateLimiter()
    app.state.websocket_manager = WebSocketManager()
    app.state.detector = ThreatDetector(settings.anomaly_enabled, settings.anomaly_contamination)
    app.state.notifier = Notifier(
        webhook_url=settings.webhook_url,
        smtp_config={
            "host": settings.smtp_host,
            "port": settings.smtp_port,
            "username": settings.smtp_username,
            "password": settings.smtp_password,
            "from": settings.alert_email_from,
            "to": settings.alert_email_to,
        },
    )
    app.state.threat_intel_service = ThreatIntelService(
        virustotal_api_key=settings.virustotal_api_key,
        alienvault_otx_api_key=settings.alienvault_otx_api_key,
        enabled=settings.enable_external_enrichment,
        timeout_seconds=settings.enrichment_timeout_seconds,
    )
    app.state.monitoring_service = MonitoringService(
        app.state.detector,
        app.state.notifier,
        app.state.websocket_manager,
        app.state.threat_intel_service,
        settings.enable_external_enrichment,
    )

    await _wait_for_database(database)
    await _seed_demo_data(app)

    try:
        yield
    finally:
        await database.close()


app = FastAPI(title=get_settings().app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(logs_router)
app.include_router(threats_router)
app.include_router(alerts_router)
app.include_router(cases_router)
app.include_router(onboarding_router)
app.include_router(tuning_router)
app.include_router(reports_router)
app.include_router(metrics_router)
app.include_router(health_router)


@app.websocket("/ws/live")
async def live_stream(websocket: WebSocket, token: str | None = None):
    await app.state.websocket_manager.connect(websocket)
    try:
        if token:
            await websocket.send_json({"event_type": "status", "payload": {"message": "connected"}})
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        app.state.websocket_manager.disconnect(websocket)
