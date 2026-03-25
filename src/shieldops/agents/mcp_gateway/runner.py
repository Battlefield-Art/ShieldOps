"""MCP Gateway Agent runner — entry point for executing gateway workflows.

Constructs the LangGraph, runs the full secure-proxy pipeline, and returns
the completed gateway state with assessments, enforcements, and anomalies.
"""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.mcp_gateway.graph import create_mcp_gateway_graph
from shieldops.agents.mcp_gateway.models import MCPGatewayState
from shieldops.observability.tracing import get_tracer

logger = structlog.get_logger()


class MCPGatewayRunner:
    """Runs MCP Gateway secure-proxy workflows.

    Usage::

        runner = MCPGatewayRunner()
        result = await runner.secure(tenant_id="acme-corp")
    """

    def __init__(self) -> None:
        graph = create_mcp_gateway_graph()
        self._app = graph.compile()
        self._runs: dict[str, MCPGatewayState] = {}

    async def secure(
        self,
        tenant_id: str,
        context: dict[str, Any] | None = None,
    ) -> MCPGatewayState:
        """Run the full MCP Gateway workflow for *tenant_id*.

        Args:
            tenant_id: The tenant whose MCP servers to secure.
            context: Optional extra context (e.g., specific endpoints).

        Returns:
            The completed ``MCPGatewayState`` with all findings.
        """
        _ = context  # reserved for future use
        request_id = f"gw-{uuid4().hex[:12]}"

        logger.info(
            "mcp_gateway_run_started",
            request_id=request_id,
            tenant_id=tenant_id,
        )

        initial_state = MCPGatewayState(
            request_id=request_id,
            tenant_id=tenant_id,
            session_start=time.monotonic(),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("mcp_gateway.secure") as span:
                span.set_attribute("mcp_gateway.request_id", request_id)
                span.set_attribute("mcp_gateway.tenant_id", tenant_id)

                final_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={"metadata": {"request_id": request_id}},
                )

                final_state = MCPGatewayState.model_validate(final_dict)

                span.set_attribute(
                    "mcp_gateway.servers",
                    len(final_state.mcp_servers),
                )
                span.set_attribute(
                    "mcp_gateway.god_keys",
                    final_state.god_keys_found,
                )
                span.set_attribute(
                    "mcp_gateway.policies",
                    len(final_state.policy_enforcements),
                )
                span.set_attribute(
                    "mcp_gateway.duration_ms",
                    final_state.session_duration_ms,
                )

            logger.info(
                "mcp_gateway_run_completed",
                request_id=request_id,
                servers=len(final_state.mcp_servers),
                god_keys=final_state.god_keys_found,
                policies=len(final_state.policy_enforcements),
                anomalies=len(final_state.traffic_anomalies),
                duration_ms=final_state.session_duration_ms,
            )

            self._runs[request_id] = final_state
            return final_state

        except Exception as exc:
            logger.error(
                "mcp_gateway_run_failed",
                request_id=request_id,
                error=str(exc),
            )
            error_state = MCPGatewayState(
                request_id=request_id,
                tenant_id=tenant_id,
                error=str(exc),
                current_step="failed",
            )
            self._runs[request_id] = error_state
            return error_state

    def get_run(self, request_id: str) -> MCPGatewayState | None:
        """Retrieve a completed run by request ID."""
        return self._runs.get(request_id)

    def list_runs(self) -> list[dict[str, Any]]:
        """List all runs with summary info."""
        return [
            {
                "request_id": rid,
                "tenant_id": s.tenant_id,
                "status": s.current_step,
                "servers": len(s.mcp_servers),
                "god_keys": s.god_keys_found,
                "policies": len(s.policy_enforcements),
                "anomalies": len(s.traffic_anomalies),
                "duration_ms": s.session_duration_ms,
                "error": s.error,
            }
            for rid, s in self._runs.items()
        ]
