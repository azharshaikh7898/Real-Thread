from datetime import datetime, timedelta, timezone

import pytest

from app.routes.cases import _build_case_document, build_case_timeline
from app.schemas import CaseCreateRequest


class FakeCursor:
    def __init__(self, documents):
        self.documents = documents
        self.index = 0

    def sort(self, field, direction=1):
        reverse = direction < 0
        self.documents.sort(key=lambda document: document.get(field), reverse=reverse)
        return self

    def limit(self, count):
        self.documents = self.documents[:count]
        return self

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
        return FakeCursor([document for document in self.documents if matches(document, query)])

    async def find_one(self, query):
        for document in self.documents:
            if matches(document, query):
                return document
        return None

    async def insert_one(self, document):
        self.documents.append(document)
        return document

    async def update_one(self, query, update):
        for document in self.documents:
            if matches(document, query):
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


def matches(document, query):
    for key, expected in query.items():
        if document.get(key) != expected:
            return False
    return True


@pytest.mark.asyncio
async def test_build_case_document_prefills_entities_from_alert_and_threat():
    now = datetime.now(timezone.utc)
    database = FakeDatabase(
        {
            'alerts': FakeCollection([
                {'id': 'alert-1', 'threat_id': 'threat-1', 'title': 'Alert title', 'message': 'Alert message', 'severity': 'high', 'created_at': now - timedelta(minutes=4)}
            ]),
            'threats': FakeCollection([
                {
                    'id': 'threat-1',
                    'log_id': 'log-1',
                    'title': 'Brute force attempt detected',
                    'description': 'Detected brute force activity',
                    'severity': 'high',
                    'source_ip': '10.0.0.20',
                    'username': 'root',
                    'rule_id': 'AUTH-001',
                    'mitre_tactic': 'Credential Access',
                    'mitre_technique': 'T1110',
                    'created_at': now - timedelta(minutes=5),
                }
            ]),
            'logs': FakeCollection([
                {
                    'id': 'log-1',
                    'timestamp': now - timedelta(minutes=6),
                    'host': 'srv-01',
                    'src_ip': '10.0.0.20',
                    'username': 'root',
                }
            ]),
        }
    )

    case = await _build_case_document(
        database,
        CaseCreateRequest(alert_id='alert-1', notes='Initial review'),
        {'username': 'admin', 'id': 'user-admin', 'role': 'admin'},
    )

    assert case['title'] == 'Brute force attempt detected'
    assert case['source_ip'] == '10.0.0.20'
    assert case['username'] == 'root'
    assert case['host'] == 'srv-01'
    assert any(entity['type'] == 'ip' for entity in case['impacted_entities'])
    assert any(entity['type'] == 'user' for entity in case['impacted_entities'])
    assert case['related_alert_ids'] == ['alert-1']
    assert case['related_threat_ids'] == ['threat-1']


@pytest.mark.asyncio
async def test_build_case_timeline_collects_related_events():
    now = datetime.now(timezone.utc)
    case = {
        'id': 'case-1',
        'title': 'Investigate brute force',
        'description': 'Detected brute force activity',
        'status': 'open',
        'disposition': 'open',
        'severity': 'high',
        'source_ip': '10.0.0.20',
        'username': 'root',
        'host': 'srv-01',
        'observed_at': now,
        'timeline_window_minutes': 60,
        'created_at': now,
    }
    database = FakeDatabase(
        {
            'logs': FakeCollection([
                {
                    'id': 'log-1',
                    'timestamp': now - timedelta(minutes=5),
                    'source': 'system',
                    'host': 'srv-01',
                    'event_type': 'auth',
                    'event_kind': 'failed_login',
                    'message': 'Failed password for invalid user root from 10.0.0.20',
                    'severity': 'warning',
                    'src_ip': '10.0.0.20',
                    'username': 'root',
                    'detected_threats': ['threat-1'],
                }
            ]),
            'threats': FakeCollection([
                {
                    'id': 'threat-1',
                    'log_id': 'log-1',
                    'title': 'Brute force attempt detected',
                    'threat_type': 'brute_force',
                    'severity': 'high',
                    'source_ip': '10.0.0.20',
                    'username': 'root',
                    'rule_id': 'AUTH-001',
                    'mitre_tactic': 'Credential Access',
                    'mitre_technique': 'T1110',
                    'created_at': now - timedelta(minutes=4),
                    'status': 'open',
                }
            ]),
            'alerts': FakeCollection([
                {
                    'id': 'alert-1',
                    'threat_id': 'threat-1',
                    'title': 'Brute force alert',
                    'message': 'Multiple failures detected',
                    'severity': 'high',
                    'acknowledged': False,
                    'created_at': now - timedelta(minutes=3),
                }
            ]),
        }
    )

    timeline = await build_case_timeline(database, case)

    assert len(timeline) >= 4
    assert timeline[0]['event_type'] == 'log' or timeline[0]['event_type'] == 'case'
    assert any(event['event_type'] == 'threat' for event in timeline)
    assert any(event['event_type'] == 'alert' for event in timeline)
    assert any(event['event_type'] == 'case' for event in timeline)
