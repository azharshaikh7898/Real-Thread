from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.core.config import get_settings


class MonitoringService:
    def __init__(self, detector, notifier, websocket_manager, threat_intel_service=None, enable_external_enrichment: bool = True) -> None:
        self.detector = detector
        self.notifier = notifier
        self.websocket_manager = websocket_manager
        self.threat_intel_service = threat_intel_service
        self.enable_external_enrichment = enable_external_enrichment

    async def ingest_log(self, database, payload: dict[str, Any], actor: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        normalized = self._normalize_event(payload)
        enrichment = self._enrich_event(payload, normalized)
        parse_success = self._parse_success(payload)
        event_timestamp = payload.get("timestamp") or now
        time_skew_seconds = abs((now - event_timestamp).total_seconds())
        log_record = {
            "id": str(uuid4()),
            "timestamp": event_timestamp,
            "received_at": now,
            "source": normalized["source"],
            "host": payload["host"],
            "event_type": payload["event_type"],
            "event_kind": self.detector.classify_event(payload),
            "message": payload["message"],
            "severity": payload.get("severity", "info"),
            "status_code": payload.get("status_code"),
            "username": payload.get("username"),
            "src_ip": payload.get("src_ip"),
            "dest_ip": payload.get("dest_ip"),
            "process": payload.get("process"),
            "event_id": payload.get("event_id"),
            "action": payload.get("action"),
            "status": payload.get("status"),
            "user_agent": payload.get("user_agent"),
            "metadata": payload.get("metadata", {}),
            "schema_version": "1.0",
            "normalized": normalized,
            "enrichment": enrichment,
            "parse_success": parse_success,
            "time_skew_seconds": round(float(time_skew_seconds), 2),
            "detected_threats": [],
            "actor": {"id": actor["id"], "username": actor["username"], "role": actor["role"]},
        }
        await database["logs"].insert_one(log_record)

        threats = await self.detector.detect(log_record, database)
        persisted_threats: list[dict[str, Any]] = []

        for threat in threats:
            if self.enable_external_enrichment and self.threat_intel_service:
                source_ip = threat.get("source_ip") or log_record.get("src_ip")
                if source_ip:
                    intel = await self.threat_intel_service.enrich_ip(str(source_ip))
                    evidence = threat.get("evidence")
                    if not isinstance(evidence, dict):
                        evidence = {}
                    evidence["threat_intel"] = intel
                    threat["evidence"] = evidence

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

    async def ingestion_health(self, database, skew_threshold_seconds: int = 300) -> dict[str, Any]:
        source_stats: dict[str, dict[str, Any]] = {}
        total_events = 0
        required_fields = ("host", "event_type", "message", "src_ip", "username")

        async for log in database["logs"].find({}):
            total_events += 1
            source = str(log.get("source") or "unknown")
            stats = source_stats.setdefault(
                source,
                {
                    "source": source,
                    "total_events": 0,
                    "parse_success_count": 0,
                    "completeness_ratio_sum": 0.0,
                    "timestamp_skew_violations": 0,
                    "last_seen": None,
                },
            )

            stats["total_events"] += 1
            if log.get("parse_success", True):
                stats["parse_success_count"] += 1

            present_fields = sum(1 for field in required_fields if log.get(field))
            stats["completeness_ratio_sum"] += present_fields / len(required_fields)

            skew = float(log.get("time_skew_seconds") or 0.0)
            if skew > skew_threshold_seconds:
                stats["timestamp_skew_violations"] += 1

            timestamp = log.get("timestamp")
            if isinstance(timestamp, datetime):
                if stats["last_seen"] is None or timestamp > stats["last_seen"]:
                    stats["last_seen"] = timestamp

        source_metrics = []
        for stats in source_stats.values():
            total = stats["total_events"] or 1
            source_metrics.append(
                {
                    "source": stats["source"],
                    "total_events": stats["total_events"],
                    "parse_success_rate": round((stats["parse_success_count"] / total) * 100, 2),
                    "field_completeness_rate": round((stats["completeness_ratio_sum"] / total) * 100, 2),
                    "timestamp_skew_violations": stats["timestamp_skew_violations"],
                    "last_seen": stats["last_seen"],
                }
            )

        source_metrics.sort(key=lambda item: item["source"])
        return {
            "total_sources": len(source_metrics),
            "total_events": total_events,
            "source_metrics": source_metrics,
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

    @staticmethod
    def _parse_success(payload: dict[str, Any]) -> bool:
        required_keys = ("host", "event_type", "message")
        return all(bool(payload.get(key)) for key in required_keys)

    @staticmethod
    def _normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": payload.get("source", "system"),
            "src_ip": payload.get("src_ip"),
            "dest_ip": payload.get("dest_ip"),
            "user": payload.get("username"),
            "host": payload.get("host"),
            "process": payload.get("process"),
            "event_id": payload.get("event_id"),
            "action": payload.get("action"),
            "status": payload.get("status") or payload.get("severity"),
        }

    @staticmethod
    def _geo_for_ip(ip: str | None) -> tuple[str | None, str | None]:
        if not ip:
            return None, None
        if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
            return "PRIVATE", "AS-PRIVATE"
        if ip.startswith("203."):
            return "TEST-NET", "AS64500"
        if ip.startswith("198."):
            return "TEST-NET", "AS64501"
        return "UNKNOWN", "AS-UNKNOWN"

    def _enrich_event(self, payload: dict[str, Any], normalized: dict[str, Any]) -> dict[str, Any]:
        settings = get_settings()
        host = str(normalized.get("host") or "")
        user = str(normalized.get("user") or "")
        src_ip = normalized.get("src_ip")
        geo_country, asn = self._geo_for_ip(src_ip)

        asset_criticality = "high" if any(token in host.lower() for token in ("srv", "prod", "db", "dc")) else "medium"
        user_role = "admin" if any(token in user.lower() for token in ("admin", "root", "svc")) else "user"

        ioc_indicator = None
        ioc_match = False
        for indicator in settings.ioc_watchlist_set:
            if indicator and (
                indicator == str(src_ip)
                or indicator == str(normalized.get("dest_ip"))
                or indicator.lower() in str(payload.get("message", "")).lower()
            ):
                ioc_match = True
                ioc_indicator = indicator
                break

        return {
            "asset_criticality": asset_criticality,
            "user_role": user_role,
            "geo_country": geo_country,
            "asn": asn,
            "ioc_match": ioc_match,
            "ioc_indicator": ioc_indicator,
            "enrichment_confidence": 0.82,
        }
