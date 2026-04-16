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
        cutoff_24h = now - timedelta(hours=24)

        if await self._is_suppressed(log, database):
            return []

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
                        rule_id="AUTH-001",
                        title="Brute force attempt detected",
                        description=f"{recent_failures} failed authentication events were observed from {source_ip} within 10 minutes.",
                        severity=severity,
                        confidence=min(0.98, 0.7 + (recent_failures * 0.03)),
                        evidence={"failed_attempts": recent_failures, "window_minutes": 10},
                        mitre_tactic="Credential Access",
                        mitre_technique="T1110",
                        response_guidance="Block offending source IP, reset affected credentials, and review successful logins after failures.",
                    ))
                    threat_types.add(threat_type)

        if event_kind == "failed_login" and source_ip:
            usernames: set[str] = set()
            recent_failures = 0
            async for candidate in database["logs"].find(
                {
                    "src_ip": source_ip,
                    "event_kind": "failed_login",
                    "timestamp": {"$gte": cutoff_10m},
                }
            ):
                recent_failures += 1
                username_candidate = candidate.get("username")
                if username_candidate:
                    usernames.add(str(username_candidate).lower())
            if recent_failures >= 8 and len(usernames) >= 3:
                threat_type = "password_spraying"
                if threat_type not in threat_types:
                    threats.append(self._build_threat(
                        log,
                        threat_type=threat_type,
                        rule_id="AUTH-002",
                        title="Password spraying pattern detected",
                        description=f"{recent_failures} failed logins from {source_ip} across {len(usernames)} accounts in 10 minutes.",
                        severity="high",
                        confidence=min(0.98, 0.72 + (len(usernames) * 0.04)),
                        evidence={"failed_attempts": recent_failures, "targeted_accounts": len(usernames), "window_minutes": 10},
                        mitre_tactic="Credential Access",
                        mitre_technique="T1110.003",
                        response_guidance="Lock targeted test accounts, block source, and verify whether any account was successfully accessed.",
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
                        rule_id="WEB-001",
                        title="Repeated unauthorized access attempts",
                        description=f"{recent_denials} denied requests were observed from {source_ip} in 5 minutes.",
                        severity="medium",
                        confidence=min(0.92, 0.65 + (recent_denials * 0.05)),
                        evidence={"denied_requests": recent_denials, "window_minutes": 5},
                        mitre_tactic="Reconnaissance",
                        mitre_technique="T1595",
                        response_guidance="Review requested paths and user agents, then apply WAF/firewall blocks where appropriate.",
                    ))
                    threat_types.add(threat_type)

        if self._looks_suspicious_payload(log):
            threat_type = "payload_abuse"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="WEB-002",
                    title="Suspicious payload detected",
                    description="The request payload or message contains injection or traversal indicators.",
                    severity="high",
                    confidence=0.9,
                    evidence={"indicator": "payload_signature"},
                    mitre_tactic="Initial Access",
                    mitre_technique="T1190",
                    response_guidance="Capture request details, block source if malicious, and validate no post-exploitation activity occurred.",
                ))
                threat_types.add(threat_type)

        lower_message = str(log.get("message", "")).lower()
        if "powershell" in lower_message and any(token in lower_message for token in ("-enc", "encodedcommand", "iex ")):
            threat_type = "suspicious_powershell"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="EXEC-001",
                    title="Suspicious PowerShell execution",
                    description="Encoded or obfuscated PowerShell command execution pattern detected.",
                    severity="high",
                    confidence=0.91,
                    evidence={"indicator": "powershell_encoded"},
                    mitre_tactic="Execution",
                    mitre_technique="T1059.001",
                    response_guidance="Isolate host, collect command-line telemetry, and verify parent process lineage.",
                ))
                threat_types.add(threat_type)

        if any(token in lower_message for token in ("scheduled task", "schtasks", "run key", "service create", "startup folder")):
            threat_type = "persistence_attempt"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="PERS-001",
                    title="Potential persistence mechanism",
                    description="Log evidence suggests startup persistence via task, registry run key, or service manipulation.",
                    severity="high",
                    confidence=0.86,
                    evidence={"indicator": "persistence_keyword"},
                    mitre_tactic="Persistence",
                    mitre_technique="T1053",
                    response_guidance="Audit startup artifacts, remove unauthorized persistence, and check host for related execution events.",
                ))
                threat_types.add(threat_type)

        if any(token in lower_message for token in ("psexec", "wmic", "remote service", "rdp", "smb")):
            threat_type = "lateral_movement"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="LAT-001",
                    title="Lateral movement indicator",
                    description="Potential remote execution or remote access pattern detected in telemetry.",
                    severity="medium",
                    confidence=0.8,
                    evidence={"indicator": "remote_movement_keyword"},
                    mitre_tactic="Lateral Movement",
                    mitre_technique="T1021",
                    response_guidance="Validate remote session legitimacy and inspect peer hosts for follow-on suspicious activity.",
                ))
                threat_types.add(threat_type)

        dest_ip = log.get("dest_ip")
        outbound_bytes = float(log.get("metadata", {}).get("outbound_bytes") or 0)
        if dest_ip and outbound_bytes >= 5_000_000:
            recent_to_destination = await database["logs"].count_documents(
                {
                    "dest_ip": dest_ip,
                    "timestamp": {"$gte": cutoff_24h},
                }
            )
            if recent_to_destination <= 2:
                threat_type = "possible_exfiltration"
                if threat_type not in threat_types:
                    threats.append(self._build_threat(
                        log,
                        threat_type=threat_type,
                        rule_id="EXFIL-001",
                        title="Possible data exfiltration",
                        description=f"Large outbound transfer ({int(outbound_bytes)} bytes) to a rare destination {dest_ip}.",
                        severity="high",
                        confidence=0.88,
                        evidence={"outbound_bytes": int(outbound_bytes), "dest_ip": dest_ip},
                        mitre_tactic="Exfiltration",
                        mitre_technique="T1048",
                        response_guidance="Review transfer context, validate destination trust, and apply containment if unauthorized.",
                    ))
                    threat_types.add(threat_type)

        if self.anomaly_enabled and self._is_anomaly(log):
            threat_type = "anomaly"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="UEBA-001",
                    title="Behavioral anomaly detected",
                    description="The event deviates from the learned baseline profile.",
                    severity="medium",
                    confidence=0.84,
                    evidence={"model": "IsolationForest", "window_minutes": 10},
                    mitre_tactic="Defense Evasion",
                    mitre_technique="T1070",
                    response_guidance="Correlate anomaly with authentication, process, and network telemetry before closing.",
                ))
                threat_types.add(threat_type)

        if username and source_ip and event_kind == "access_denied" and "admin" in username.lower():
            threat_type = "privileged_access_probe"
            if threat_type not in threat_types:
                threats.append(self._build_threat(
                    log,
                    threat_type=threat_type,
                    rule_id="PRIV-001",
                    title="Privileged account probing",
                    description=f"Denied access attempts were made against privileged user {username} from {source_ip}.",
                    severity="high",
                    confidence=0.87,
                    evidence={"target_user": username},
                    mitre_tactic="Privilege Escalation",
                    mitre_technique="T1078",
                    response_guidance="Validate account change history and enforce MFA or temporary lock on the privileged account.",
                ))
                threat_types.add(threat_type)

        return threats

    async def _is_suppressed(self, log: dict[str, Any], database) -> bool:
        source = str(log.get("source") or "")
        host = str(log.get("host") or "")
        username = str(log.get("username") or "")
        src_ip = str(log.get("src_ip") or "")
        threat_type = self.classify_event(log)

        async for rule in database["tuning_rules"].find({"enabled": True}):
            scope = str(rule.get("rule_scope") or "")
            match_value = str(rule.get("match_value") or "")
            action = str(rule.get("action") or "")
            if action == "threshold":
                continue
            if scope == "threat_type" and match_value == threat_type and action in {"whitelist", "suppress"}:
                return True
            if scope == "source" and match_value == source and action in {"whitelist", "suppress"}:
                return True
            if scope == "host" and match_value == host and action in {"whitelist", "suppress"}:
                return True
            if scope == "user" and match_value == username and action in {"whitelist", "suppress"}:
                return True
            if scope == "ip" and match_value == src_ip and action in {"whitelist", "suppress"}:
                return True
        return False

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
        rule_id: str,
        mitre_tactic: str,
        mitre_technique: str,
        response_guidance: str,
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "log_id": log["id"],
            "threat_type": threat_type,
            "rule_id": rule_id,
            "rule_version": "1.0",
            "title": title,
            "description": description,
            "severity": severity,
            "source_ip": log.get("src_ip"),
            "username": log.get("username"),
            "confidence": round(float(confidence), 2),
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
            "response_guidance": response_guidance,
            "created_at": datetime.now(timezone.utc),
            "status": "open",
            "evidence": evidence,
        }
