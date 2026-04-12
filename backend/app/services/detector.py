from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import numpy as np
from sklearn.ensemble import IsolationForest


class ThreatDetector:
    def __init__(self, anomaly_enabled: bool = True, contamination: float = 0.08) -> None:
        self.anomaly_enabled = anomaly_enabled
        self.contamination = contamination
        self._model = IsolationForest(
            n_estimators=120,
            contamination=contamination,
            random_state=42,
        )
        self._trained = False
        self._train_model()

    def _train_model(self) -> None:
        rng = np.random.default_rng(42)
        samples = []
        for _ in range(500):
            message_length = float(rng.normal(140, 35))
            failed_login = 0.0
            success_login = 1.0
            status_code = float(rng.choice([200, 200, 200, 204, 302]))
            severity_flag = 0.0
            admin_flag = 0.0
            samples.append([message_length, failed_login, success_login, status_code, severity_flag, admin_flag])

        self._model.fit(np.asarray(samples, dtype=float))
        self._trained = True

    def classify_event(self, log: dict[str, Any]) -> str:
        message = str(log.get("message", "")).lower()
        event_type = str(log.get("event_type", "")).lower()
        status_code = log.get("status_code")

        if any(keyword in message for keyword in ("failed password", "authentication failure", "invalid user", "login failed")):
            return "failed_login"
        if status_code in (401, 403):
            return "access_denied"
        if any(keyword in message for keyword in ("select ", "union select", "../", "<script", "cmd.exe", "powershell")):
            return "payload_abuse"
        if event_type in {"auth_failed", "failed_login"}:
            return "failed_login"
        if event_type in {"http", "web"}:
            return "web_request"
        if event_type in {"ssh", "auth"}:
            return "auth"
        return event_type or "generic"

    def _feature_vector(self, log: dict[str, Any]) -> np.ndarray:
        message = str(log.get("message", ""))
        lower_message = message.lower()
        status_code = float(log.get("status_code") or 0)
        return np.asarray([
            [
                float(len(message)),
                1.0 if "failed" in lower_message else 0.0,
                1.0 if "success" in lower_message else 0.0,
                status_code,
                1.0 if str(log.get("severity", "")).lower() in {"warning", "error", "critical"} else 0.0,
                1.0 if any(token in lower_message for token in ("admin", "root", "privilege")) else 0.0,
            ]
        ], dtype=float)

    async def detect(self, log: dict[str, Any], database) -> list[dict[str, Any]]:
        threats: list[dict[str, Any]] = []
        threat_types: set[str] = set()
        now = log.get("timestamp") or datetime.now(timezone.utc)
        event_kind = self.classify_event(log)
        source_ip = log.get("src_ip")
        username = log.get("username")
        cutoff_10m = now - timedelta(minutes=10)
        cutoff_5m = now - timedelta(minutes=5)

        if event_kind == "failed_login" and source_ip:
            recent_failures = await database["logs"].count_documents(
                {
                    "src_ip": source_ip,
                    "event_kind": "failed_login",
                    "timestamp": {"$gte": cutoff_10m},
                }
            )
            if recent_failures >= 5:
                threat_type = "brute_force"
                severity = "critical" if recent_failures >= 10 else "high"
                if threat_type not in threat_types:
                    threats.append(self._build_threat(
                        log,
                        threat_type=threat_type,
                        title="Brute force attempt detected",
                        description=f"{recent_failures} failed authentication events were observed from {source_ip} within 10 minutes.",
                        severity=severity,
                        confidence=min(0.98, 0.7 + (recent_failures * 0.03)),
                        evidence={"failed_attempts": recent_failures, "window_minutes": 10},
                    ))
                    threat_types.add(threat_type)

        if log.get("status_code") in (401, 403) and source_ip:
            recent_denials = await database["logs"].count_documents(
                {
                    "src_ip": source_ip,
                    "status_code": {"$in": [401, 403]},
                    "timestamp": {"$gte": cutoff_5m},
                }
            )
            if recent_denials >= 4:
                threat_type = "access_abuse"
                if threat_type not in threat_types:
                    threats.append(self._build_threat(
                        log,
                        threat_type=threat_type,
                        title="Repeated unauthorized access attempts",
                        description=f"{recent_denials} denied requests were observed from {source_ip} in 5 minutes.",
                        severity="medium",
                        confidence=min(0.92, 0.65 + (recent_denials * 0.05)),
                        evidence={"denied_requests": recent_denials, "window_minutes": 5},
                    ))
                    threat_types.add(threat_type)

        if self._looks_suspicious_payload(log):
            threat_type = "payload_abuse"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    title="Suspicious payload detected",
                    description="The request payload or message contains injection or traversal indicators.",
                    severity="high",
                    confidence=0.9,
                    evidence={"indicator": "payload_signature"},
                ))
                threat_types.add(threat_type)

        if self.anomaly_enabled and self._is_anomaly(log):
            threat_type = "anomaly"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    title="Behavioral anomaly detected",
                    description="The event deviates from the learned baseline profile.",
                    severity="medium",
                    confidence=0.84,
                    evidence={"model": "IsolationForest", "window_minutes": 10},
                ))
                threat_types.add(threat_type)

        if username and source_ip and event_kind == "access_denied" and "admin" in username.lower():
            threat_type = "privileged_access_probe"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    title="Privileged account probing",
                    description=f"Denied access attempts were made against privileged user {username} from {source_ip}.",
                    severity="high",
                    confidence=0.87,
                    evidence={"target_user": username},
                ))
                threat_types.add(threat_type)

        return threats

    def _is_anomaly(self, log: dict[str, Any]) -> bool:
        if not self._trained:
            return False
        feature_vector = self._feature_vector(log)
        prediction = self._model.predict(feature_vector)[0]
        return prediction == -1

    @staticmethod
    def _looks_suspicious_payload(log: dict[str, Any]) -> bool:
        message = str(log.get("message", "")).lower()
        signatures = ("../", "union select", "drop table", "<script", "cmd.exe", "powershell", "or 1=1", "passwd")
        return any(signature in message for signature in signatures)

    @staticmethod
    def _build_threat(
        log: dict[str, Any],
        *,
        threat_type: str,
        title: str,
        description: str,
        severity: str,
        confidence: float,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "log_id": log["id"],
            "threat_type": threat_type,
            "title": title,
            "description": description,
            "severity": severity,
            "source_ip": log.get("src_ip"),
            "username": log.get("username"),
            "confidence": round(float(confidence), 2),
            "created_at": datetime.now(timezone.utc),
            "status": "open",
            "evidence": evidence,
        }
