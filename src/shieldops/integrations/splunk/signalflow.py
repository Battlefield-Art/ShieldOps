"""Splunk SignalFlow Analytics Client.

Execute SignalFlow programs against Splunk Observability Cloud for
real-time streaming analytics on agent metrics.

API: POST https://stream.{realm}.signalfx.com/v2/signalflow/execute
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


class SignalFlowProgram(BaseModel):
    """A SignalFlow program definition."""

    name: str
    program: str  # SignalFlow code
    description: str = ""
    resolution_ms: int = 10000  # 10s default


class SignalFlowResult(BaseModel):
    """Result from a SignalFlow execution."""

    program_name: str
    data_points: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    executed_at_ms: int = Field(default_factory=lambda: int(time.time() * 1000))


class SignalFlowClient:
    """Execute SignalFlow programs for real-time agent analytics.

    When *token* is empty the client returns synthetic/empty results
    suitable for testing.
    """

    def __init__(self, realm: str = "us1", token: str = ""):
        self._realm = realm
        self._token = token
        self._base_url = f"https://stream.{realm}.signalfx.com"

    async def execute(
        self,
        program: str,
        start_ms: int = 0,
        stop_ms: int = 0,
        resolution_ms: int = 10000,
        program_name: str = "",
    ) -> SignalFlowResult:
        """Execute a SignalFlow program.

        Parameters
        ----------
        program:
            SignalFlow source code to execute.
        start_ms / stop_ms:
            Time range in epoch milliseconds. ``0`` means *now* (server-side).
        resolution_ms:
            Desired data resolution.
        program_name:
            Optional label for the result.
        """
        url = f"{self._base_url}/v2/signalflow/execute"

        if not self._token:
            logger.debug("signalflow_dry_run", program=program[:120])
            return SignalFlowResult(
                program_name=program_name or "dry_run",
                metadata={"mode": "dry_run", "program": program},
            )

        try:
            import httpx  # noqa: WPS433

            body: dict[str, Any] = {
                "program": program,
                "resolution": resolution_ms,
            }
            if start_ms:
                body["start"] = start_ms
            if stop_ms:
                body["stop"] = stop_ms

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json=body,
                    headers={
                        "X-SF-Token": self._token,
                        "Content-Type": "application/json",
                    },
                    timeout=60.0,
                )
                resp.raise_for_status()
                data = resp.json() if resp.content else {}
                logger.info("signalflow_executed", status=resp.status_code)
                return SignalFlowResult(
                    program_name=program_name or "query",
                    data_points=data.get("data", []),
                    metadata=data.get("metadata", {}),
                )
        except Exception as exc:
            logger.error("signalflow_error", error=str(exc))
            return SignalFlowResult(
                program_name=program_name or "error",
                metadata={"error": str(exc)},
            )

    # ------------------------------------------------------------------
    # Pre-built SignalFlow programs for ShieldOps monitoring
    # ------------------------------------------------------------------

    def agent_cpu_program(self, agent_type: str = "*") -> str:
        """SignalFlow: agent CPU utilization by type."""
        return (
            f'data("agent.cpu.utilization", '
            f'filter=filter("agent_type", "{agent_type}"))'
            f'.mean(by="agent_type").publish()'
        )

    def agent_latency_p95_program(self, agent_type: str = "*") -> str:
        """SignalFlow: P95 agent execution latency."""
        return (
            f'data("agent.duration.seconds", '
            f'filter=filter("agent_type", "{agent_type}"))'
            f'.percentile(95, by="agent_type").publish()'
        )

    def llm_cost_program(self) -> str:
        """SignalFlow: LLM cost per minute by model."""
        return 'data("llm.cost.dollars").sum(by="model").mean(over="1m").publish()'

    def agent_success_rate_program(self, agent_type: str = "*") -> str:
        """SignalFlow: agent success rate over 5 minutes."""
        return (
            f'A = data("agent.executions.total", '
            f'filter=filter("agent_type", "{agent_type}")).sum(over="5m")\n'
            f'B = data("agent.executions.success", '
            f'filter=filter("agent_type", "{agent_type}")).sum(over="5m")\n'
            f"(B / A).publish()"
        )

    def incident_mttr_program(self) -> str:
        """SignalFlow: Mean Time to Resolve by severity."""
        return 'data("incident.resolution.seconds").mean(by="severity").mean(over="1h").publish()'

    def opa_policy_violation_rate_program(self) -> str:
        """SignalFlow: OPA policy violation rate over 10 minutes."""
        return 'data("opa.policy.violations").sum(by="policy_name").sum(over="10m").publish()'

    def get_all_programs(self) -> list[SignalFlowProgram]:
        """Return all pre-built SignalFlow programs."""
        return [
            SignalFlowProgram(
                name="agent_cpu",
                program=self.agent_cpu_program(),
                description="Mean agent CPU utilization grouped by agent type",
            ),
            SignalFlowProgram(
                name="agent_latency_p95",
                program=self.agent_latency_p95_program(),
                description="P95 agent execution latency grouped by agent type",
            ),
            SignalFlowProgram(
                name="llm_cost",
                program=self.llm_cost_program(),
                description="LLM cost per minute grouped by model",
            ),
            SignalFlowProgram(
                name="agent_success_rate",
                program=self.agent_success_rate_program(),
                description="Agent success rate over a 5-minute window",
            ),
            SignalFlowProgram(
                name="incident_mttr",
                program=self.incident_mttr_program(),
                description="Mean Time to Resolve grouped by severity (1h window)",
            ),
            SignalFlowProgram(
                name="opa_violations",
                program=self.opa_policy_violation_rate_program(),
                description="OPA policy violation rate over 10 minutes",
            ),
        ]
