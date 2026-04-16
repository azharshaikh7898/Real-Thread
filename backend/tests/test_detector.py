from datetime import datetime, timedelta, timezone

import pytest

from app.services.detector import ThreatDetector


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    async def count_documents(self, query):
        return sum(1 for document in self.documents if matches(document, query))

    def find(self, query):
        return FakeCursor([document for document in self.documents if matches(document, query)])


class FakeCursor:
    def __init__(self, documents):
        self.documents = documents
        self.index = 0

    def __aiter__(self):
        self.index = 0
        return self

    async def __anext__(self):
        if self.index >= len(self.documents):
            raise StopAsyncIteration
        item = self.documents[self.index]
        self.index += 1
        return item


class FakeDatabase:
    def __init__(self, logs):
        self._collections = {"logs": FakeCollection(logs)}

    def __getitem__(self, name):
        if name not in self._collections:
            self._collections[name] = FakeCollection([])
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


@pytest.mark.asyncio
async def test_suspicious_powershell_detection_includes_mitre_mapping():
    detector = ThreatDetector(anomaly_enabled=False)
    database = FakeDatabase([])
    threat_log = {
        "id": "log-3",
        "timestamp": datetime.now(timezone.utc),
        "message": "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQ==",
        "event_type": "process",
        "severity": "high",
        "src_ip": "198.51.100.27",
    }

    threats = await detector.detect(threat_log, database)

    hit = next((threat for threat in threats if threat["threat_type"] == "suspicious_powershell"), None)
    assert hit is not None
    assert hit["mitre_technique"] == "T1059.001"
    assert hit["rule_id"] == "EXEC-001"


@pytest.mark.asyncio
async def test_exfiltration_detection_for_rare_destination():
    detector = ThreatDetector(anomaly_enabled=False)
    now = datetime.now(timezone.utc)
    database = FakeDatabase(
        [
            {
                "dest_ip": "203.0.113.99",
                "timestamp": now - timedelta(hours=2),
            }
        ]
    )
    threat_log = {
        "id": "log-4",
        "timestamp": now,
        "message": "Outbound transfer complete",
        "event_type": "network",
        "severity": "warning",
        "src_ip": "10.0.0.15",
        "dest_ip": "203.0.113.99",
        "metadata": {"outbound_bytes": 7_500_000},
    }

    threats = await detector.detect(threat_log, database)

    assert any(threat["threat_type"] == "possible_exfiltration" for threat in threats)
