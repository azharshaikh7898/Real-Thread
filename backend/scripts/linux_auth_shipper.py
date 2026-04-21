#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import socket
import sys
import time
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

import requests
from requests import RequestException


SYSLOG_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w./-]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)
NGINX_ACCESS_PATTERN = re.compile(
    r'^(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>[^\"]*?) (?P<protocol>HTTP/[0-9.]+)" '
    r'(?P<status>\d{3}) (?P<body_bytes>\S+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)
IP_PATTERN = re.compile(r"\b(?:from\s+|rhost=)(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\b")
USER_PATTERN = re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<username>[A-Za-z0-9_.@-]+)")
SUSPICIOUS_PATH_PATTERN = re.compile(r"(\.{2}/|<script|union\s+select|cmd\.exe|powershell|/etc/passwd|/wp-admin|/phpmyadmin)", re.IGNORECASE)


@dataclass
class ShipperConfig:
    api_base: str
    username: str
    password: str
    log_file: Path
    mode: str
    source: str
    poll_interval: float
    read_from_start: bool


class BackendClient:
    def __init__(self, api_base: str, username: str, password: str) -> None:
        self.api_base = api_base.rstrip("/")
        self.username = username
        self.password = password
        self.session = requests.Session()

    def login(self) -> None:
        response = self.session.post(
            f"{self.api_base}/auth/login",
            json={"username": self.username, "password": self.password},
            timeout=10,
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("Login succeeded but no access token was returned")
        self.session.headers.update({"Authorization": f"Bearer {token}"})

    def ingest_log(self, payload: dict[str, Any]) -> requests.Response:
        return self.session.post(f"{self.api_base}/logs", json=payload, timeout=10)


def parse_syslog_line(line: str, fallback_host: str, source: str) -> dict[str, Any] | None:
    stripped = line.strip()
    parsed = SYSLOG_PATTERN.match(stripped)
    if not parsed:
        parsed = ISO_SYSLOG_PATTERN.match(stripped)
    if not parsed:
        return None

    message = parsed.group("message")
    process = parsed.group("process")
    host = parsed.group("host") or fallback_host
    lower_message = message.lower()

    event_type = "generic_event"
    severity = "info"
    status = None

    if "failed password" in lower_message or "authentication failure" in lower_message or "invalid user" in lower_message:
        event_type = "auth_failure"
        severity = "medium"
        status = "failed"
    elif "accepted password" in lower_message or "accepted publickey" in lower_message:
        event_type = "auth_success"
        severity = "low"
        status = "success"
    elif "sudo" in process.lower() or "sudo" in lower_message:
        event_type = "privilege_use"
        severity = "medium"
    elif "session opened" in lower_message or "session closed" in lower_message:
        event_type = "session_activity"
        severity = "info"

    ip_match = IP_PATTERN.search(message)
    user_match = USER_PATTERN.search(message)

    return {
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": source,
        "host": host,
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "src_ip": ip_match.group("ip") if ip_match else None,
        "username": user_match.group("username") if user_match else None,
        "process": process,
        "status": status,
        "metadata": {
            "collector": "multi_source_shipper",
            "collector_mode": "syslog",
            "raw_line": line.strip(),
        },
    }


def parse_auth_line(line: str, fallback_host: str, source: str) -> dict[str, Any] | None:
    parsed = parse_syslog_line(line, fallback_host, source)
    if not parsed:
        return None

    # Keep auth mode focused on real authentication telemetry to avoid flooding
    # the backend with low-signal session/sudo chatter from host activity.
    if parsed.get("event_type") not in {"auth_failure", "auth_success"}:
        return None

    parsed["metadata"]["collector_mode"] = "auth"
    return parsed


def parse_nginx_line(line: str, fallback_host: str, source: str) -> dict[str, Any] | None:
    parsed = NGINX_ACCESS_PATTERN.match(line.strip())
    if not parsed:
        return None

    remote_addr = parsed.group("remote_addr")
    method = parsed.group("method")
    path = parsed.group("path")
    status = int(parsed.group("status"))
    user_agent = parsed.group("user_agent")
    referer = parsed.group("referer")
    lower_path = path.lower()

    event_type = "web_request"
    severity = "info"
    message = f"{method} {path} returned {status}"

    if status in (401, 403):
        event_type = "access_denied"
        severity = "medium"
    elif status >= 500:
        event_type = "server_error"
        severity = "medium"

    if SUSPICIOUS_PATH_PATTERN.search(path):
        event_type = "payload_abuse"
        severity = "high"
        message = f"Suspicious request path observed: {method} {path}"
    elif any(token in lower_path for token in ("login", "admin", "wp-login", "xmlrpc.php", "phpmyadmin")) and status in (401, 403):
        event_type = "access_abuse"
        severity = "high"

    return {
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": source,
        "host": fallback_host,
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "src_ip": remote_addr,
        "username": None,
        "process": "nginx",
        "status_code": status,
        "status": "failed" if status >= 400 else "success",
        "user_agent": user_agent,
        "metadata": {
            "collector": "multi_source_shipper",
            "collector_mode": "nginx",
            "method": method,
            "path": path,
            "referer": referer,
            "raw_line": line.strip(),
        },
    }


def parse_line(line: str, fallback_host: str, source: str, mode: str) -> dict[str, Any] | None:
    normalized_mode = mode.lower()
    if normalized_mode == "nginx":
        return parse_nginx_line(line, fallback_host, source)
    if normalized_mode == "syslog":
        return parse_syslog_line(line, fallback_host, source)
    return parse_auth_line(line, fallback_host, source)


def follow(path: Path, poll_interval: float, read_from_start: bool):
    with path.open("r", encoding="utf-8", errors="ignore") as stream:
        if not read_from_start:
            stream.seek(0, os.SEEK_END)

        current_inode = path.stat().st_ino
        while True:
            line = stream.readline()
            if line:
                yield line
                continue

            try:
                latest_inode = path.stat().st_ino
            except FileNotFoundError:
                time.sleep(poll_interval)
                continue

            if latest_inode != current_inode:
                stream.close()
                stream = path.open("r", encoding="utf-8", errors="ignore")
                current_inode = latest_inode
            else:
                time.sleep(poll_interval)


def parse_args() -> ShipperConfig:
    parser = argparse.ArgumentParser(description="Tail Linux auth, nginx, or syslog logs and send normalized events to RTMAP backend")
    parser.add_argument("--api-base", default=os.getenv("RTMAP_API_BASE", "http://localhost:8001"))
    parser.add_argument("--username", default=os.getenv("RTMAP_USERNAME", "admin"))
    parser.add_argument("--password", default=os.getenv("RTMAP_PASSWORD", ""))
    parser.add_argument("--log-file", default=os.getenv("RTMAP_LOG_FILE", "/var/log/auth.log"))
    parser.add_argument("--mode", default=os.getenv("RTMAP_SOURCE_MODE", "auth"), choices=["auth", "nginx", "syslog"])
    parser.add_argument("--source", default=os.getenv("RTMAP_SOURCE", "linux"))
    parser.add_argument("--poll-interval", type=float, default=float(os.getenv("RTMAP_POLL_INTERVAL", "0.5")))
    parser.add_argument("--read-from-start", action="store_true")
    args = parser.parse_args()

    if not args.password:
        parser.error("Backend password is required. Set --password or RTMAP_PASSWORD.")

    return ShipperConfig(
        api_base=args.api_base,
        username=args.username,
        password=args.password,
        log_file=Path(args.log_file),
        mode=args.mode,
        source=args.source,
        poll_interval=max(0.1, args.poll_interval),
        read_from_start=args.read_from_start,
    )


def main() -> int:
    config = parse_args()
    if not config.log_file.exists():
        print(f"Log file not found: {config.log_file}", file=sys.stderr)
        return 1

    fallback_host = socket.gethostname()
    client = BackendClient(config.api_base, config.username, config.password)

    try:
        client.login()
    except Exception as exc:
        print(f"Failed to authenticate: {exc}", file=sys.stderr)
        return 1

    print(f"Streaming {config.log_file} to {config.api_base}/logs as {config.mode} source '{config.source}'")
    try:
        for line in follow(config.log_file, config.poll_interval, config.read_from_start):
            payload = parse_line(line, fallback_host, config.source, config.mode)
            if not payload:
                continue

            try:
                response = client.ingest_log(payload)
                if response.status_code == 401:
                    client.login()
                    response = client.ingest_log(payload)

                if response.status_code == 429:
                    # Respect backend rate limits and keep the shipper alive.
                    time.sleep(max(1.0, config.poll_interval * 4))
                    continue

                if response.ok:
                    print(f"sent event_type={payload['event_type']} host={payload['host']}")
                    continue

                print(f"ingest failed ({response.status_code}): {response.text}", file=sys.stderr)
            except RequestException as exc:
                print(f"transient ingest error: {exc}", file=sys.stderr)
                time.sleep(max(1.0, config.poll_interval * 4))
                continue
    except KeyboardInterrupt:
        print("Stopped log shipper")
        return 0
    except Exception as exc:
        print(f"Shipper error: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())