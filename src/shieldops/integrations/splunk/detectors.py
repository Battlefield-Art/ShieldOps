"""Splunk Observability Detector Definitions.

Pre-built detectors (alerts) for monitoring ShieldOps agent health.
Uses SignalFlow for real-time condition evaluation.

Detectors map to the Splunk Observability Cloud ``/v2/detector`` API.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class DetectorSeverity(StrEnum):
    CRITICAL = "Critical"
    MAJOR = "Major"
    MINOR = "Minor"
    WARNING = "Warning"
    INFO = "Info"


class DetectorDefinition(BaseModel):
    """A Splunk detector definition."""

    name: str
    description: str
    program: str  # SignalFlow program
    severity: DetectorSeverity
    notification_channels: list[str] = Field(default_factory=list)


class SplunkDetectorManager:
    """Manage Splunk detectors for ShieldOps agent monitoring.

    Provides a catalogue of pre-built detectors that cover the most
    important operational signals for an autonomous SRE agent platform.
    """

    def __init__(self, realm: str = "us1", token: str = ""):
        self._realm = realm
        self._token = token
        self._base_url = f"https://api.{realm}.signalfx.com"

    def get_default_detectors(self) -> list[DetectorDefinition]:
        """Return pre-built detectors for ShieldOps."""
        return [
            DetectorDefinition(
                name="Agent High Failure Rate",
                description="Fires when agent failure rate exceeds 20% over 10 minutes",
                program=(
                    'detect(when(data("agent.success_rate")'
                    '.mean(over="10m") < 0.8))'
                    '.publish("agent_failure")'
                ),
                severity=DetectorSeverity.CRITICAL,
                notification_channels=["pagerduty-shieldops", "slack-incidents"],
            ),
            DetectorDefinition(
                name="Agent Latency P95 Spike",
                description=("Fires when P95 agent execution latency exceeds 30 seconds"),
                program=(
                    'detect(when(data("agent.duration.seconds")'
                    ".percentile(95) > 30))"
                    '.publish("agent_latency_spike")'
                ),
                severity=DetectorSeverity.MAJOR,
                notification_channels=["slack-incidents"],
            ),
            DetectorDefinition(
                name="LLM Cost Spike",
                description=("Fires when LLM spend exceeds $5/minute (sustained 5 min)"),
                program=(
                    'detect(when(data("llm.cost.dollars")'
                    '.sum().mean(over="5m") > 5))'
                    '.publish("llm_cost_spike")'
                ),
                severity=DetectorSeverity.MAJOR,
                notification_channels=["slack-finops", "email-billing"],
            ),
            DetectorDefinition(
                name="Incident MTTR Degradation",
                description=(
                    "Fires when mean time to resolve exceeds 60 minutes "
                    "for Critical severity over 1 hour"
                ),
                program=(
                    'detect(when(data("incident.resolution.seconds", '
                    'filter=filter("severity", "critical"))'
                    '.mean(over="1h") > 3600))'
                    '.publish("mttr_degradation")'
                ),
                severity=DetectorSeverity.WARNING,
                notification_channels=["slack-incidents"],
            ),
            DetectorDefinition(
                name="OPA Policy Violation Surge",
                description=("Fires when OPA policy violations exceed 50 in 10 minutes"),
                program=(
                    'detect(when(data("opa.policy.violations")'
                    '.sum(over="10m") > 50))'
                    '.publish("opa_violation_surge")'
                ),
                severity=DetectorSeverity.CRITICAL,
                notification_channels=["pagerduty-shieldops", "slack-security"],
            ),
            DetectorDefinition(
                name="Agent Heartbeat Missing",
                description=("Fires when no agent heartbeat received for 5 minutes"),
                program=(
                    'detect(when(data("agent.heartbeat")'
                    '.count(over="5m") == 0))'
                    '.publish("agent_heartbeat_missing")'
                ),
                severity=DetectorSeverity.CRITICAL,
                notification_channels=["pagerduty-shieldops"],
            ),
        ]

    async def sync_detectors(self) -> dict[str, Any]:
        """Sync default detectors to Splunk Observability Cloud.

        In token-less mode returns a dry-run summary.
        """
        detectors = self.get_default_detectors()
        if not self._token:
            logger.debug("detector_sync_dry_run", count=len(detectors))
            return {
                "status": "dry_run",
                "detectors": [d.name for d in detectors],
                "count": len(detectors),
            }

        results: list[dict[str, Any]] = []
        try:
            import httpx  # noqa: WPS433

            async with httpx.AsyncClient() as client:
                for det in detectors:
                    resp = await client.post(
                        f"{self._base_url}/v2/detector",
                        json={
                            "name": det.name,
                            "description": det.description,
                            "programText": det.program,
                            "rules": [
                                {
                                    "severity": det.severity.value,
                                    "notifications": [
                                        {"type": "Slack", "channel": ch}
                                        for ch in det.notification_channels
                                    ],
                                }
                            ],
                        },
                        headers={
                            "X-SF-Token": self._token,
                            "Content-Type": "application/json",
                        },
                        timeout=30.0,
                    )
                    results.append({"name": det.name, "status": resp.status_code})
        except Exception as exc:
            logger.error("detector_sync_error", error=str(exc))
            return {"status": "error", "error": str(exc)}

        logger.info("detector_sync_complete", count=len(results))
        return {"status": "ok", "results": results}
