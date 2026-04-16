from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.core.security import get_current_user
from app.db import get_database
from app.schemas import ReportArtifact

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/final", response_model=ReportArtifact)
async def final_report(request: Request, current_user = Depends(get_current_user), database = Depends(get_database)):
    monitoring_service = request.app.state.monitoring_service
    summary = await monitoring_service.summary(database)
    ingestion_health = await monitoring_service.ingestion_health(database)
    tuning_rules = []
    async for rule in database["tuning_rules"].find({}):
        tuning_rules.append(rule)
    cases = []
    async for case in database["cases"].find({}):
        cases.append(case)
    threats = []
    async for threat in database["threats"].find({}):
        threats.append(threat)

    detection_catalog = []
    for threat in threats:
        detection_catalog.append(
            {
                "rule_id": threat.get("rule_id"),
                "name": threat.get("title"),
                "severity": threat.get("severity"),
                "mitre_tactic": threat.get("mitre_tactic"),
                "mitre_technique": threat.get("mitre_technique"),
                "response_guidance": threat.get("response_guidance"),
            }
        )

    dashboard_inventory = [
        {"name": "Operational Overview", "kpis": ["logs", "threats", "alerts", "health"]},
        {"name": "Ingestion Health", "kpis": ["parse success", "field completeness", "timestamp skew"]},
        {"name": "Alert Trends", "kpis": ["severity", "MITRE tactic", "open alerts"]},
        {"name": "Case Investigation", "kpis": ["owner", "status", "disposition"]},
    ]

    return ReportArtifact(
        executive_summary={
            "scope": "Real-time threat monitoring and analysis platform",
            "key_outcomes": {
                "total_logs": summary["total_logs"],
                "total_threats": summary["total_threats"],
                "open_alerts": summary["open_alerts"],
                "cases": len(cases),
            },
            "risk_posture": "Improving through normalized ingestion, MITRE-mapped detections, and investigation workflow.",
        },
        architecture={
            "collection": "FastAPI backend with local database and WebSocket broadcast",
            "data_sources": ["system", "web", "network", "identity", "cloud"],
            "normalization": "schema_version 1.0 with enrichment for asset criticality, user role, geo, and IOC reputation",
            "coverage_summary": ingestion_health,
        },
        detection_catalog=detection_catalog,
        dashboards=dashboard_inventory,
        triage_workflow={
            "intake": "Open case from alert or threat",
            "pivot": "User, host, source IP, destination IP",
            "timeline": "Case timeline built from correlated logs, threats, and alerts",
            "disposition": ["true_positive", "false_positive", "benign_positive", "closed"],
        },
        tuning={
            "rules": tuning_rules,
            "summary": {
                "total_rules": len(tuning_rules),
                "enabled_rules": sum(1 for rule in tuning_rules if rule.get("enabled", True)),
            },
        },
        roadmap=[
            "Expand direct collectors for Windows, Linux, web, network, identity, and cloud telemetry",
            "Add threshold baselines and tuning history charts",
            "Add SOAR-style response actions and approval workflow",
            "Generate PDF/Markdown evidence export bundle",
        ],
    )
