from datetime import datetime, timedelta, timezone

import pytest

from app.services.detector import ThreatDetector


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    async def count_documents(self, query):
        return sum(1 for document in self.documents if matches(document, query))


class FakeDatabase:
    def __init__(self, logs):
        self._collections = {"logs": FakeCollection(logs)}

    def __getitem__(self, name):
        return self._collections[name]


def matches(document, query):
    for key, expected in query.items():
        value = document.get(key)
        if isinstance(expected, dict):
            if "$gte" in expected and not (value >= expected["$gte"]):
                return False
            if "$in" in expected and value not in expected["$in"]:
                return False
        elif value != expected:
            return False
    return True


@pytest.mark.asyncio
async def test_brute_force_detection_triggers_after_five_failures():
    detector = ThreatDetector(anomaly_enabled=False)
    now = datetime.now(timezone.utc)
    source_ip = "10.0.0.20"
    logs = [
        {
            "src_ip": source_ip,
            "event_kind": "failed_login",
            "timestamp": now - timedelta(minutes=1),
            "status_code": None,
        }
        for _ in range(5)
    ]
    database = FakeDatabase(logs)
    threat_log = {
        "id": "log-1",
        "timestamp": now,
        "message": "Failed password for invalid user root from 10.0.0.20",
        "event_type": "auth",
        "severity": "warning",
        "src_ip": source_ip,
        "username": "root",
    }

    threats = await detector.detect(threat_log, database)

    assert any(threat["threat_type"] == "brute_force" for threat in threats)


@pytest.mark.asyncio
async def test_payload_abuse_detection_triggers_on_injection_signature():
    detector = ThreatDetector(anomaly_enabled=False)
    database = FakeDatabase([])
    threat_log = {
        "id": "log-2",
        "timestamp": datetime.now(timezone.utc),
        "message": "GET /?id=1 UNION SELECT password FROM users",
        "event_type": "http",
        "severity": "warning",
        "src_ip": "203.0.113.44",
    }

    threats = await detector.detect(threat_log, database)

    assert any(threat["threat_type"] == "payload_abuse" for threat in threats)
