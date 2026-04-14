from __future__ import annotations

import asyncio
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any


def _serialize_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return {"__type__": "datetime", "value": value.isoformat()}
    if isinstance(value, dict):
        return {key: _serialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    return value


def _deserialize_value(value: Any) -> Any:
    if isinstance(value, dict):
        if value.get("__type__") == "datetime" and "value" in value:
            return datetime.fromisoformat(value["value"])
        return {key: _deserialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_deserialize_value(item) for item in value]
    return value


def _matches(document: dict[str, Any], query: dict[str, Any]) -> bool:
    for key, expected in query.items():
        value = document.get(key)
        if isinstance(expected, dict):
            if "$gte" in expected and (value is None or value < expected["$gte"]):
                return False
            if "$in" in expected and value not in expected["$in"]:
                return False
        elif value != expected:
            return False
    return True


def _sort_value(value: Any) -> Any:
    if value is None:
        return datetime.min
    return value


class LocalCursor:
    def __init__(self, documents: list[dict[str, Any]]) -> None:
        self._documents = documents
        self._index = 0

    def sort(self, field: str, direction: int = 1) -> "LocalCursor":
        reverse = direction < 0
        self._documents.sort(key=lambda document: _sort_value(document.get(field)), reverse=reverse)
        return self

    def limit(self, count: int) -> "LocalCursor":
        self._documents = self._documents[:count]
        return self

    def __aiter__(self) -> "LocalCursor":
        self._index = 0
        return self

    async def __anext__(self) -> dict[str, Any]:
        if self._index >= len(self._documents):
            raise StopAsyncIteration
        document = self._documents[self._index]
        self._index += 1
        return deepcopy(document)


class LocalCollection:
    def __init__(self, database: "LocalDatabase", name: str) -> None:
        self._database = database
        self._name = name

    async def insert_one(self, document: dict[str, Any]) -> dict[str, Any]:
        async with self._database._lock:
            self._database._state[self._name].append(deepcopy(document))
            await self._database._save_locked()
        return document

    async def insert_many(self, documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        async with self._database._lock:
            for document in documents:
                self._database._state[self._name].append(deepcopy(document))
            await self._database._save_locked()
        return documents

    def find(self, query: dict[str, Any] | None = None) -> LocalCursor:
        query = query or {}
        documents = [deepcopy(document) for document in self._database._state[self._name] if _matches(document, query)]
        return LocalCursor(documents)

    async def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        for document in self._database._state[self._name]:
            if _matches(document, query):
                return deepcopy(document)
        return None

    async def count_documents(self, query: dict[str, Any]) -> int:
        return sum(1 for document in self._database._state[self._name] if _matches(document, query))

    async def update_one(self, query: dict[str, Any], update: dict[str, Any]) -> dict[str, int]:
        updated_count = 0
        async with self._database._lock:
            for document in self._database._state[self._name]:
                if _matches(document, query):
                    set_values = update.get("$set", {})
                    document.update(deepcopy(set_values))
                    updated_count = 1
                    break
            if updated_count:
                await self._database._save_locked()
        return {"modified_count": updated_count}


class LocalDatabase:
    def __init__(self, storage_path: str) -> None:
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._state = self._load_state()

    def __getitem__(self, name: str) -> LocalCollection:
        if name not in self._state:
            self._state[name] = []
        return LocalCollection(self, name)

    async def command(self, name: str) -> dict[str, str]:
        if name != "ping":
            raise ValueError(f"Unsupported command: {name}")
        return {"ok": "1"}

    async def close(self) -> None:
        async with self._lock:
            await self._save_locked()

    def _load_state(self) -> dict[str, list[dict[str, Any]]]:
        if not self.storage_path.exists():
            return {"users": [], "logs": [], "threats": [], "alerts": []}

        with self.storage_path.open("r", encoding="utf-8") as file_handle:
            raw_state = json.load(file_handle)

        state: dict[str, list[dict[str, Any]]] = {"users": [], "logs": [], "threats": [], "alerts": []}
        for name, documents in raw_state.items():
            if isinstance(documents, list):
                state[name] = [_deserialize_value(document) for document in documents]
        return state

    async def _save_locked(self) -> None:
        serialized_state = {name: [_serialize_value(document) for document in documents] for name, documents in self._state.items()}
        temp_path = self.storage_path.with_suffix(".tmp")
        with temp_path.open("w", encoding="utf-8") as file_handle:
            json.dump(serialized_state, file_handle, ensure_ascii=True, indent=2)
        temp_path.replace(self.storage_path)