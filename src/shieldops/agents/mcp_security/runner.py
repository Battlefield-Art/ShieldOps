"""MCP Security Agent runner — entry point for executing MCP security scans.

Takes scan scope (endpoints), constructs the LangGraph, runs it end-to-end,
and returns the completed scan state.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.mcp_security.graph import create_mcp_security_graph
from shieldops.agents.mcp_security.models import MCPSecurityState
from shieldops.agents.mcp_security.nodes import set_toolkit
from shieldops.agents.mcp_security.tools import MCPSecurityToolkit
from shieldops.observability.tracing import get_tracer
from shieldops.security.mcp_connection_registry import MCPConnectionRegistry
from shieldops.security.mcp_security_gateway import MCPSecurityGateway
from shieldops.security.mcp_supply_chain_scanner import MCPSupplyChainScanner
from shieldops.security.mcp_zero_trust_enforcer import MCPZeroTrustEnforcer

logger = structlog.get_logger()


class MCPSecurityRunner:
    """Runs MCP security scan workflows.

    Usage:
        runner = MCPSecurityRunner()
        result = await runner.scan(
            endpoints=["https://mcp-server-1.example.com"],
            context={"scan_depth": "deep"},
        )
    """

    def __init__(
        self,
        gateway: MCPSecurityGateway | None = None,
        supply_chain: MCPSupplyChainScanner | None = None,
        zero_trust: MCPZeroTrustEnforcer | None = None,
        registry: MCPConnectionRegistry | None = None,
    ) -> None:
        self._gateway = gateway or MCPSecurityGateway()
        self._supply_chain = supply_chain or MCPSupplyChainScanner()
        self._zero_trust = zero_trust or MCPZeroTrustEnforcer()
        self._registry = registry or MCPConnectionRegistry()

        self._toolkit = MCPSecurityToolkit(
            gateway=self._gateway,
            supply_chain=self._supply_chain,
            zero_trust=self._zero_trust,
            registry=self._registry,
        )
        set_toolkit(self._toolkit)

        graph = create_mcp_security_graph()
        self._app = graph.compile()

        self._scans: dict[str, MCPSecurityState] = {}

    async def scan(
        self,
        endpoints: list[str],
        context: dict[str, Any] | None = None,
    ) -> MCPSecurityState:
        """Run a full MCP security scan.

        Args:
            endpoints: List of MCP server endpoints to scan.
            context: Optional context dict (scan_depth, policy_set, etc.).

        Returns:
            The completed MCPSecurityState with findings and policies.
        """
        ctx = context or {}
        scan_id = f"mcp-scan-{uuid4().hex[:12]}"

        logger.info(
            "mcp_security_scan_started",
            scan_id=scan_id,
            endpoint_count=len(endpoints),
            scan_depth=ctx.get("scan_depth", "standard"),
        )

        initial_state = MCPSecurityState(
            scan_id=scan_id,
            scan_scope=endpoints,
            policy_set=ctx.get("policy_set", {}),
            scan_depth=ctx.get("scan_depth", "standard"),
        )

        try:
            tracer = get_tracer("shieldops.agents")
            with tracer.start_as_current_span("mcp_security.scan") as span:
                span.set_attribute("mcp_security.scan_id", scan_id)
                span.set_attribute("mcp_security.endpoint_count", len(endpoints))
                span.set_attribute("mcp_security.scan_depth", ctx.get("scan_depth", "standard"))

                final_state_dict = await self._app.ainvoke(
                    initial_state.model_dump(),
                    config={
                        "metadata": {
                            "scan_id": scan_id,
                        },
                    },
                )

                final_state = MCPSecurityState.model_validate(final_state_dict)

                if final_state.scan_start:
                    final_state.scan_duration_ms = int(
                        (datetime.now(UTC) - final_state.scan_start).total_seconds() * 1000
                    )

                span.set_attribute("mcp_security.duration_ms", final_state.scan_duration_ms)
                span.set_attribute(
                    "mcp_security.vulnerabilities", len(final_state.config_vulnerabilities)
                )
                span.set_attribute("mcp_security.god_keys", len(final_state.god_key_risks))

            logger.info(
                "mcp_security_scan_completed",
                scan_id=scan_id,
                duration_ms=final_state.scan_duration_ms,
                servers_found=len(final_state.mcp_servers_found),
                vulnerabilities=len(final_state.config_vulnerabilities),
                god_keys=len(final_state.god_key_risks),
                policies=len(final_state.policies_generated),
                steps=len(final_state.reasoning_chain),
            )

            self._scans[scan_id] = final_state
            return final_state

        except Exception as e:
            logger.error(
                "mcp_security_scan_failed",
                scan_id=scan_id,
                error=str(e),
            )
            error_state = MCPSecurityState(
                scan_id=scan_id,
                scan_scope=endpoints,
                error=str(e),
                current_step="failed",
            )
            self._scans[scan_id] = error_state
            return error_state

    async def evaluate_server(self, endpoint: str) -> dict[str, Any]:
        """Quick evaluation of a single MCP server endpoint.

        Args:
            endpoint: The MCP server endpoint to evaluate.

        Returns:
            Dict with server info, trust evaluation, and risk score.
        """
        server_id = endpoint.replace("https://", "").replace("http://", "").replace("/", "_")

        logger.info("mcp_security.evaluating_server", endpoint=endpoint, server_id=server_id)

        config = await self._toolkit.analyze_server_config(server_id, endpoint)
        auth = await self._toolkit.check_auth_configuration(server_id, "none")
        trust = self._zero_trust.evaluate_trust(server_id)

        return {
            "server_id": server_id,
            "endpoint": endpoint,
            "config_analysis": config,
            "auth_analysis": auth,
            "trust_evaluation": trust,
        }

    def get_scan(self, scan_id: str) -> MCPSecurityState | None:
        """Retrieve a completed scan by ID."""
        return self._scans.get(scan_id)

    def list_scans(self) -> list[dict[str, Any]]:
        """List all scans with summary info."""
        return [
            {
                "scan_id": sid,
                "status": state.current_step,
                "servers_found": len(state.mcp_servers_found),
                "vulnerabilities": len(state.config_vulnerabilities),
                "god_keys": len(state.god_key_risks),
                "policies": len(state.policies_generated),
                "duration_ms": state.scan_duration_ms,
                "error": state.error,
            }
            for sid, state in self._scans.items()
        ]

    @property
    def gateway(self) -> MCPSecurityGateway:
        return self._gateway

    @property
    def supply_chain(self) -> MCPSupplyChainScanner:
        return self._supply_chain

    @property
    def zero_trust(self) -> MCPZeroTrustEnforcer:
        return self._zero_trust

    @property
    def registry(self) -> MCPConnectionRegistry:
        return self._registry
