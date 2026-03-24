"""Dynatrace Problem Definitions for ShieldOps.

Pre-built custom event rules and metric anomaly detectors that map to
Dynatrace's Settings API (``/api/v2/settings/objects``) for automatic
problem detection.

Each rule defines a metric key, threshold, and severity level. In
production these would be synced via the Dynatrace Settings 2.0 API
(schema ``builtin:anomaly-detection.metric-events``).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel

logger = structlog.get_logger()


class ProblemSeverity(StrEnum):
    """Dynatrace event severity levels used in custom event rules."""

    ERROR = "ERROR_EVENT"
    CUSTOM_ALERT = "CUSTOM_ALERT"
    CUSTOM_INFO = "CUSTOM_INFO"


class DynatraceProblemRule(BaseModel):
    """A Dynatrace custom event / metric anomaly rule definition."""

    name: str
    description: str
    metric_key: str
    threshold: float
    severity: str = ProblemSeverity.CUSTOM_ALERT
    entity_selector: str = ""
    aggregation: str = "AVG"  # AVG, SUM, MIN, MAX, COUNT, PERCENTILE
    slide_window_minutes: int = 10
    deal_alerting_on_missing_data: bool = False


class DynatraceProblemManager:
    """Manage Dynatrace problem rules for ShieldOps agent monitoring.

    Provides a catalogue of pre-built problem detection rules covering
    the most important operational signals for autonomous SRE agents.
    """

    def __init__(self, environment_id: str = "", api_token: str = ""):
        self._env_id = environment_id
        self._token = api_token
        self._base_url = f"https://{environment_id}.live.dynatrace.com"

    def get_default_rules(self) -> list[DynatraceProblemRule]:
        """Return 6 pre-built problem rules for ShieldOps agent monitoring."""
        return [
            DynatraceProblemRule(
                name="Agent High Failure Rate",
                description=(
                    "Fires when agent success rate drops below 80% over a 10-minute sliding window"
                ),
                metric_key="shieldops.agent.success_rate",
                threshold=0.8,
                severity=ProblemSeverity.ERROR,
                aggregation="AVG",
                slide_window_minutes=10,
            ),
            DynatraceProblemRule(
                name="Agent Latency P95 Spike",
                description=("Fires when P95 agent execution latency exceeds 30 seconds"),
                metric_key="shieldops.agent.duration",
                threshold=30.0,
                severity=ProblemSeverity.CUSTOM_ALERT,
                aggregation="PERCENTILE",
                slide_window_minutes=10,
            ),
            DynatraceProblemRule(
                name="LLM Cost Spike",
                description=("Fires when LLM cost exceeds $5 per minute sustained over 5 minutes"),
                metric_key="shieldops.llm.cost_dollars",
                threshold=5.0,
                severity=ProblemSeverity.CUSTOM_ALERT,
                aggregation="SUM",
                slide_window_minutes=5,
            ),
            DynatraceProblemRule(
                name="Incident MTTR Degradation",
                description=(
                    "Fires when mean time to resolve exceeds 60 minutes "
                    "for critical severity incidents over 1 hour"
                ),
                metric_key="shieldops.incident.resolution_seconds",
                threshold=3600.0,
                severity=ProblemSeverity.CUSTOM_ALERT,
                aggregation="AVG",
                slide_window_minutes=60,
            ),
            DynatraceProblemRule(
                name="OPA Policy Violation Surge",
                description=("Fires when OPA policy violations exceed 50 in 10 minutes"),
                metric_key="shieldops.opa.policy_violations",
                threshold=50.0,
                severity=ProblemSeverity.ERROR,
                aggregation="SUM",
                slide_window_minutes=10,
            ),
            DynatraceProblemRule(
                name="Agent Heartbeat Missing",
                description=("Fires when no agent heartbeat is received for 5 minutes"),
                metric_key="shieldops.agent.heartbeat",
                threshold=0.0,
                severity=ProblemSeverity.ERROR,
                aggregation="COUNT",
                slide_window_minutes=5,
                deal_alerting_on_missing_data=True,
            ),
        ]

    async def sync_rules(self) -> dict[str, Any]:
        """Sync default problem rules to Dynatrace Settings 2.0 API.

        In token-less mode returns a dry-run summary.
        """
        rules = self.get_default_rules()
        if not self._token:
            logger.debug("dynatrace_problem_sync_dry_run", count=len(rules))
            return {
                "status": "dry_run",
                "rules": [r.name for r in rules],
                "count": len(rules),
            }

        results: list[dict[str, Any]] = []
        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                for rule in rules:
                    body = {
                        "schemaId": "builtin:anomaly-detection.metric-events",
                        "scope": "environment",
                        "value": {
                            "summary": rule.name,
                            "description": rule.description,
                            "enabled": True,
                            "eventType": rule.severity,
                            "metricId": rule.metric_key,
                            "aggregationType": rule.aggregation,
                            "threshold": rule.threshold,
                            "slidingWindow": rule.slide_window_minutes,
                            "dealertingOnMissingData": rule.deal_alerting_on_missing_data,
                        },
                    }
                    if rule.entity_selector:
                        body["value"]["entityFilter"] = rule.entity_selector

                    resp = await client.post(
                        f"{self._base_url}/api/v2/settings/objects",
                        json=[body],
                        headers={
                            "Authorization": f"Api-Token {self._token}",
                            "Content-Type": "application/json",
                        },
                        timeout=30.0,
                    )
                    results.append({"name": rule.name, "status": resp.status_code})
        except Exception as exc:
            logger.error("dynatrace_problem_sync_error", error=str(exc))
            return {"status": "error", "error": str(exc)}

        logger.info("dynatrace_problem_sync_complete", count=len(results))
        return {"status": "ok", "results": results}
