from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import get_settings


class MonitoringService:
    def __init__(self, detector, notifier, websocket_manager) -> None:
        self.detector = detector
        self.notifier = notifier
        self.websocket_manager = websocket_manager

    async def ingest_log(self, database, payload: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        log_record = {
            "id": str(uuid4()),
            "timestamp": payload.get("timestamp") or now,
            "received_at": now,
            "source": payload.get("source", "system"),
            "host": payload["host"],
            "event_type": payload["event_type"],
            "event_kind": self.detector.classify_event(payload),
            "message": payload["message"],
            "severity": payload.get("severity", "info"),
            "status_code": payload.get("status_code"),
            "username": payload.get("username"),
            "src_ip": payload.get("src_ip"),
            "user_agent": payload.get("user_agent"),
            "metadata": payload.get("metadata", {}),
            "detected_threats": [],
            "actor": {"id": actor["id"], "username": actor["username"], "role": actor["role"]},
        }
        await database["logs"].insert_one(log_record)

        threats = await self.detector.detect(log_record, database)
        persisted_threats: list[dict[str, Any]] = []

        for threat in threats:
            await database["threats"].insert_one(threat)
            alert = self._build_alert(threat)
            await database["alerts"].insert_one(alert)
            await self.notifier.notify(alert)
            await self.websocket_manager.broadcast({"event_type": "threat", "payload": threat, "created_at": datetime.now(timezone.utc).isoformat()})
            await self.websocket_manager.broadcast({"event_type": "alert", "payload": alert, "created_at": datetime.now(timezone.utc).isoformat()})
            persisted_threats.append(threat)

        if persisted_threats:
            log_record["detected_threats"] = [threat["id"] for threat in persisted_threats]
            await database["logs"].update_one({"id": log_record["id"]}, {"$set": {"detected_threats": log_record["detected_threats"]}})

        await self.websocket_manager.broadcast({"event_type": "log", "payload": log_record, "created_at": datetime.now(timezone.utc).isoformat()})
        return {"log": log_record, "threats": persisted_threats}

    async def summary(self, database) -> dict[str, Any]:
        total_logs = await database["logs"].count_documents({})
        total_threats = await database["threats"].count_documents({})
        open_alerts = await database["alerts"].count_documents({"acknowledged": False})
        high_severity_threats = await database["threats"].count_documents({"severity": {"$in": ["high", "critical"]}})
        return {
            "total_logs": total_logs,
            "total_threats": total_threats,
            "open_alerts": open_alerts,
            "high_severity_threats": high_severity_threats,
            "system_status": "operational",
        }

    @staticmethod
    def _build_alert(threat: dict[str, Any]) -> dict[str, Any]:
        channel = "dashboard"
        delivery_status = "pending"
        settings = get_settings()
        if settings.webhook_url or settings.smtp_host:
            channel = "dashboard,external"
            delivery_status = "sent"
        return {
            "id": str(uuid4()),
            "threat_id": threat["id"],
            "title": threat["title"],
            "message": threat["description"],
            "severity": threat["severity"],
            "channel": channel,
            "delivery_status": delivery_status,
            "acknowledged": False,
            "created_at": datetime.now(timezone.utc),
        }
