from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx


class ThreatIntelService:
    def __init__(
        self,
        virustotal_api_key: str | None,
        alienvault_otx_api_key: str | None,
        enabled: bool = True,
        timeout_seconds: int = 6,
    ) -> None:
        self.enabled = enabled
        self.virustotal_api_key = virustotal_api_key
        self.alienvault_otx_api_key = alienvault_otx_api_key
        self.timeout_seconds = timeout_seconds

    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        intel: dict[str, Any] = {
            "ip": ip,
            "enabled": self.enabled,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "providers": {},
            "risk_score": 0,
            "summary": "No external intelligence available",
        }

        if not self.enabled:
            intel["summary"] = "External enrichment is disabled"
            return intel

        tasks: list[tuple[str, Any]] = []
        if self.virustotal_api_key:
            tasks.append(("virustotal", self._fetch_virustotal_ip(ip)))
        if self.alienvault_otx_api_key:
            tasks.append(("alienvault_otx", self._fetch_otx_ip(ip)))

        if not tasks:
            intel["summary"] = "VirusTotal and AlienVault OTX keys are not configured"
            return intel

        results = await asyncio.gather(*(task for _, task in tasks), return_exceptions=True)
        for (provider_name, _), provider_result in zip(tasks, results):
            if isinstance(provider_result, Exception):
                intel["providers"][provider_name] = {
                    "available": False,
                    "error": str(provider_result),
                }
            else:
                intel["providers"][provider_name] = {
                    "available": True,
                    **provider_result,
                }

        intel["risk_score"] = self._compute_risk_score(intel["providers"])
        intel["summary"] = self._build_summary(intel)
        return intel

    async def _fetch_virustotal_ip(self, ip: str) -> dict[str, Any]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": self.virustotal_api_key}
        timeout = httpx.Timeout(self.timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            return {
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
                "analysis": {
                    "malicious": int(stats.get("malicious", 0) or 0),
                    "suspicious": int(stats.get("suspicious", 0) or 0),
                    "harmless": int(stats.get("harmless", 0) or 0),
                    "undetected": int(stats.get("undetected", 0) or 0),
                },
            }

    async def _fetch_otx_ip(self, ip: str) -> dict[str, Any]:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.alienvault_otx_api_key}
        timeout = httpx.Timeout(self.timeout_seconds)

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", []) or []

            top_pulse_names = []
            for pulse in pulses[:3]:
                if isinstance(pulse, dict) and pulse.get("name"):
                    top_pulse_names.append(str(pulse["name"]))

            return {
                "country_code": data.get("country_code"),
                "asn": data.get("asn"),
                "reputation": data.get("reputation"),
                "pulse_count": int(pulse_info.get("count", 0) or 0),
                "top_pulses": top_pulse_names,
            }

    @staticmethod
    def _compute_risk_score(providers: dict[str, Any]) -> int:
        score = 0

        vt = providers.get("virustotal")
        if isinstance(vt, dict) and vt.get("available"):
            analysis = vt.get("analysis", {})
            malicious = int(analysis.get("malicious", 0) or 0)
            suspicious = int(analysis.get("suspicious", 0) or 0)
            score += min(70, malicious * 12 + suspicious * 6)

        otx = providers.get("alienvault_otx")
        if isinstance(otx, dict) and otx.get("available"):
            pulse_count = int(otx.get("pulse_count", 0) or 0)
            score += min(30, pulse_count * 3)

        return min(100, score)

    @staticmethod
    def _build_summary(intel: dict[str, Any]) -> str:
        score = int(intel.get("risk_score", 0) or 0)
        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 30:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "unknown"

        providers = intel.get("providers", {})
        available_count = 0
        if isinstance(providers, dict):
            for value in providers.values():
                if isinstance(value, dict) and value.get("available"):
                    available_count += 1

        return f"Risk {level} (score {score}/100) from {available_count} intelligence provider(s)"
