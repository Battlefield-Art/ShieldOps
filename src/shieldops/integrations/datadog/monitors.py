"""Datadog Monitor Definitions for ShieldOps agents.

Pre-built monitors (alerts) for monitoring ShieldOps agent health.
Uses Datadog Monitor API: POST /api/v1/monitor.

Each monitor definition maps to a Datadog monitor resource that can be
synced via the API or managed as Terraform ``datadog_monitor`` resources.
"""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class DatadogMonitor(BaseModel):
    """A Datadog monitor definition."""

    name: str
    type: str = "metric alert"
    query: str
    message: str
    tags: list[str] = Field(default_factory=list)
    priority: int = 3
    thresholds: dict[str, float] = Field(default_factory=dict)


class DatadogMonitorManager:
    """Manage Datadog monitors for ShieldOps agent monitoring.

    Provides a catalogue of pre-built monitors that cover the most
    important operational signals for an autonomous SRE agent platform.
    """

    def __init__(self, api_key: str = "", app_key: str = "", site: str = "datadoghq.com"):
        self._api_key = api_key
        self._app_key = app_key
        self._base_url = f"https://api.{site}"

    def _headers(self) -> dict[str, str]:
        return {
            "DD-API-KEY": self._api_key,
            "DD-APPLICATION-KEY": self._app_key,
            "Content-Type": "application/json",
        }

    def get_default_monitors(self) -> list[DatadogMonitor]:
        """Return 6 pre-built monitors for ShieldOps.

        Monitors cover:
        1. Agent failure rate
        2. Agent latency P95
        3. LLM cost spike
        4. Incident MTTR degradation
        5. Agent error rate
        6. OPA policy violations
        """
        return [
            DatadogMonitor(
                name="ShieldOps Agent High Failure Rate",
                type="metric alert",
                query=(
                    "avg(last_10m):avg:shieldops.agent.success_rate"
                    "{platform:shieldops} by {agent_type} < 0.8"
                ),
                message=(
                    "Agent {{agent_type.name}} failure rate exceeded 20% over the last "
                    "10 minutes. Current success rate: {{value}}.\n\n"
                    "@pagerduty-shieldops @slack-incidents"
                ),
                tags=["team:sre", "service:shieldops", "category:reliability"],
                priority=1,
                thresholds={"critical": 0.8, "warning": 0.9},
            ),
            DatadogMonitor(
                name="ShieldOps Agent Latency P95 Spike",
                type="metric alert",
                query=(
                    "avg(last_10m):p95:shieldops.agent.duration"
                    "{platform:shieldops} by {agent_type} > 30"
                ),
                message=(
                    "Agent {{agent_type.name}} P95 latency exceeded 30s. "
                    "Current P95: {{value}}s.\n\n"
                    "@slack-incidents"
                ),
                tags=["team:sre", "service:shieldops", "category:performance"],
                priority=2,
                thresholds={"critical": 30, "warning": 20},
            ),
            DatadogMonitor(
                name="ShieldOps LLM Cost Spike",
                type="metric alert",
                query=("sum(last_5m):sum:shieldops.llm.cost.dollars{platform:shieldops} > 5"),
                message=(
                    "LLM spend exceeded $5 in the last 5 minutes. "
                    "Current spend: ${{value}}.\n\n"
                    "@slack-finops @email-billing"
                ),
                tags=["team:finops", "service:shieldops", "category:cost"],
                priority=2,
                thresholds={"critical": 5, "warning": 3},
            ),
            DatadogMonitor(
                name="ShieldOps Incident MTTR Degradation",
                type="metric alert",
                query=(
                    "avg(last_1h):avg:shieldops.incident.resolution_seconds"
                    "{platform:shieldops,severity:critical} > 3600"
                ),
                message=(
                    "Mean time to resolve for Critical incidents exceeded 60 minutes "
                    "over the last hour. Current MTTR: {{value}}s.\n\n"
                    "@slack-incidents"
                ),
                tags=["team:sre", "service:shieldops", "category:reliability"],
                priority=3,
                thresholds={"critical": 3600, "warning": 1800},
            ),
            DatadogMonitor(
                name="ShieldOps Agent Error Rate",
                type="metric alert",
                query=(
                    "sum(last_10m):sum:shieldops.agent.errors"
                    "{platform:shieldops} by {agent_type} > 100"
                ),
                message=(
                    "Agent {{agent_type.name}} error count exceeded 100 in 10 minutes. "
                    "Current count: {{value}}.\n\n"
                    "@slack-incidents @pagerduty-shieldops"
                ),
                tags=["team:sre", "service:shieldops", "category:errors"],
                priority=1,
                thresholds={"critical": 100, "warning": 50},
            ),
            DatadogMonitor(
                name="ShieldOps OPA Policy Violation Surge",
                type="metric alert",
                query=(
                    "sum(last_10m):sum:shieldops.opa.policy.violations{platform:shieldops} > 50"
                ),
                message=(
                    "OPA policy violations exceeded 50 in the last 10 minutes. "
                    "Current count: {{value}}. Possible unauthorized agent actions.\n\n"
                    "@pagerduty-shieldops @slack-security"
                ),
                tags=["team:security", "service:shieldops", "category:compliance"],
                priority=1,
                thresholds={"critical": 50, "warning": 25},
            ),
        ]

    async def sync_monitors(self) -> dict[str, Any]:
        """Sync default monitors to Datadog.

        In key-less mode returns a dry-run summary.
        """
        monitors = self.get_default_monitors()
        if not self._api_key or not self._app_key:
            logger.debug("monitor_sync_dry_run", count=len(monitors))
            return {
                "status": "dry_run",
                "monitors": [m.name for m in monitors],
                "count": len(monitors),
            }

        results: list[dict[str, Any]] = []
        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                for mon in monitors:
                    resp = await client.post(
                        f"{self._base_url}/api/v1/monitor",
                        json={
                            "name": mon.name,
                            "type": mon.type,
                            "query": mon.query,
                            "message": mon.message,
                            "tags": mon.tags,
                            "priority": mon.priority,
                            "options": {"thresholds": mon.thresholds},
                        },
                        headers=self._headers(),
                        timeout=30.0,
                    )
                    results.append({"name": mon.name, "status": resp.status_code})
        except Exception as exc:
            logger.error("monitor_sync_error", error=str(exc))
            return {"status": "error", "error": str(exc)}

        logger.info("monitor_sync_complete", count=len(results))
        return {"status": "ok", "results": results}
