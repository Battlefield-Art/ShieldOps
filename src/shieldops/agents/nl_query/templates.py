"""NL Query SOC workflow templates (#235)."""

from __future__ import annotations

from typing import Any

SOC_TEMPLATES: dict[str, dict[str, Any]] = {
    "daily_threat_briefing": {
        "name": "Daily Threat Briefing",
        "description": "Summary of last 24h security posture for SOC standup",
        "question": (
            "Show me all critical and high severity alerts in the last 24 hours grouped by source"
        ),
        "category": "executive",
        "format": "summary",
    },
    "weekly_compliance_summary": {
        "name": "Weekly Compliance Summary",
        "description": "Compliance posture changes week-over-week",
        "question": "Show me all compliance findings by framework in the last 7 days",
        "category": "compliance",
        "format": "markdown_table",
    },
    "monthly_executive_report": {
        "name": "Monthly Executive Report",
        "description": "CISO-ready monthly security posture report",
        "question": "Show me MTTD, MTTR, total incidents, and agent ROI for the last 30 days",
        "category": "executive",
        "format": "summary",
    },
    "failed_auth_patterns": {
        "name": "Failed Authentication Patterns",
        "description": "Brute-force and credential-stuffing detection",
        "question": "Show me failed login attempts grouped by source IP in the last 24 hours",
        "category": "security",
        "format": "markdown_table",
    },
    "lateral_movement_hunt": {
        "name": "Lateral Movement Hunt",
        "description": "Cross-host behavior suggesting lateral movement",
        "question": "Show me hosts with unusual outbound connections in the last 7 days",
        "category": "security",
        "format": "markdown_table",
    },
}


def list_templates() -> list[dict[str, Any]]:
    """Return all available SOC workflow templates."""
    return [{"id": k, **v} for k, v in SOC_TEMPLATES.items()]


def get_template(template_id: str) -> dict[str, Any] | None:
    """Return a specific template by ID or None if not found."""
    tpl = SOC_TEMPLATES.get(template_id)
    if not tpl:
        return None
    return {"id": template_id, **tpl}
