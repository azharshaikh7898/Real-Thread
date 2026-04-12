from __future__ import annotations

import asyncio
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx


class Notifier:
    def __init__(self, webhook_url: str | None = None, smtp_config: dict[str, Any] | None = None) -> None:
        self.webhook_url = webhook_url
        self.smtp_config = smtp_config or {}

    async def notify(self, alert: dict[str, Any]) -> None:
        tasks = []
        if self.webhook_url:
            tasks.append(self._send_webhook(alert))
        if self.smtp_config.get("host") and self.smtp_config.get("to") and self.smtp_config.get("from"):
            tasks.append(asyncio.to_thread(self._send_email, alert))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _send_webhook(self, alert: dict[str, Any]) -> None:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.post(self.webhook_url, json=alert)

    def _send_email(self, alert: dict[str, Any]) -> None:
        message = EmailMessage()
        message["From"] = self.smtp_config["from"]
        message["To"] = self.smtp_config["to"]
        message["Subject"] = f"{alert['severity'].upper()} threat alert: {alert['title']}"
        message.set_content(alert["message"])

        with smtplib.SMTP(self.smtp_config["host"], int(self.smtp_config.get("port", 587))) as server:
            server.starttls()
            if self.smtp_config.get("username") and self.smtp_config.get("password"):
                server.login(self.smtp_config["username"], self.smtp_config["password"])
            server.send_message(message)
