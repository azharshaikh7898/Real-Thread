from datetime import datetime, timezone

import pytest

from app.routes.onboarding import _validate_sample
from app.services.detector import ThreatDetector


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


class FakeCollection:
    def __init__(self, documents):
        self.documents = documents

    def find(self, query):
        return FakeCursor([document for document in self.documents if all(document.get(k) == v for k, v in query.items())])

    async def find_one(self, query):
        for document in self.documents:
            if all(document.get(k) == v for k, v in query.items()):
                return document
        return None

    async def insert_one(self, document):
        self.documents.append(document)
        return document

    async def update_one(self, query, update):
        for document in self.documents:
            if all(document.get(k) == v for k, v in query.items()):
                document.update(update.get('$set', {}))
                return {'modified_count': 1}
        return {'modified_count': 0}


class FakeDatabase:
    def __init__(self, collections):
        self._collections = collections

    def __getitem__(self, name):
        if name not in self._collections:
            self._collections[name] = FakeCollection([])
        return self._collections[name]


@pytest.mark.asyncio
async def test_onboarding_validation_detects_missing_fields():
    result = _validate_sample(
        'windows',
        {
            'host': 'srv-01',
            'message': 'Security event',
            'username': 'alice',
        },
    )

    assert result.parse_success is False
    assert 'event_id' in result.missing_fields


@pytest.mark.asyncio
async def test_tuning_rule_suppresses_matching_events():
    detector = ThreatDetector(anomaly_enabled=False)
    database = FakeDatabase(
        {
            'logs': FakeCollection([
                {
                    'id': 'log-1',
                    'src_ip': '10.0.0.20',
                    'event_kind': 'failed_login',
                    'timestamp': datetime.now(timezone.utc),
                }
            ]),
            'tuning_rules': FakeCollection([
                {
                    'id': 'rule-1',
                    'name': 'Suppress test source',
                    'rule_scope': 'ip',
                    'match_value': '10.0.0.20',
                    'action': 'suppress',
                    'enabled': True,
                }
            ]),
        }
    )

    threats = await detector.detect(
        {
            'id': 'log-2',
            'timestamp': datetime.now(timezone.utc),
            'message': 'Failed password for invalid user root from 10.0.0.20',
            'event_type': 'auth',
            'severity': 'warning',
            'src_ip': '10.0.0.20',
            'username': 'root',
        },
        database,
    )

    assert threats == []
