"""Tool functions for the MCP Security Agent.

Bridge MCP security engines to the agent's LangGraph nodes.
Each tool is a self-contained async function that queries internal
engines and returns structured data.
"""

from typing import Any

import structlog

from shieldops.security.mcp_connection_registry import (
    DownstreamResource,
    MCPConnectionRegistry,
    ResourceType,
)
from shieldops.security.mcp_security_gateway import (
    AuthRequirement,
    MCPSecurityGateway,
)
from shieldops.security.mcp_supply_chain_scanner import (
    MCPComponentType,
    MCPSupplyChainScanner,
)
from shieldops.security.mcp_zero_trust_enforcer import (
    MCPZeroTrustEnforcer,
    ZeroTrustPolicy,
)

logger = structlog.get_logger()


class MCPSecurityToolkit:
    """Collection of tools available to the MCP security agent.

    Injected into nodes at graph construction time to decouple agent logic
    from specific engine implementations.
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

    async def discover_mcp_servers(self, endpoints: list[str]) -> list[dict[str, Any]]:
        """Discover and enumerate MCP servers from a list of endpoints.

        In production this would probe each endpoint via HTTP/SSE or stdio.
        Returns structured server info for each discovered server.
        """
        discovered: list[dict[str, Any]] = []
        for endpoint in endpoints:
            server_id = endpoint.replace("https://", "").replace("http://", "").replace("/", "_")
            server_info = {
                "endpoint": endpoint,
                "server_id": server_id,
                "name": server_id,
                "version": "unknown",
                "transport": "http_sse" if endpoint.startswith("http") else "stdio",
                "reachable": True,
                "tools_count": 0,
                "auth_type": "none",
            }
            discovered.append(server_info)
            logger.info("mcp_security.server_discovered", endpoint=endpoint, server_id=server_id)
        return discovered

    async def analyze_server_config(self, server_id: str, endpoint: str) -> dict[str, Any]:
        """Analyze security configuration for a single MCP server."""
        vulnerabilities: list[dict[str, Any]] = []

        # Check transport security
        if not endpoint.startswith("https://"):
            vulnerabilities.append(
                {
                    "type": "unencrypted_transport",
                    "severity": "high",
                    "description": f"Server {server_id} not using TLS — traffic is plaintext",
                    "remediation": "Enable HTTPS/TLS on the MCP server endpoint",
                }
            )

        # Register in zero-trust enforcer for tracking
        is_encrypted = endpoint.startswith("https://")
        self._zero_trust.register_server(
            server_id=server_id,
            endpoint=endpoint,
            auth_configured=False,
            transport_encrypted=is_encrypted,
        )

        return {
            "server_id": server_id,
            "vulnerabilities": vulnerabilities,
            "transport_encrypted": is_encrypted,
            "config_analyzed": True,
        }

    async def check_auth_configuration(self, server_id: str, auth_type: str) -> dict[str, Any]:
        """Check authentication configuration for a server."""
        issues: list[str] = []
        if auth_type == "none":
            issues.append("No authentication configured — any agent can invoke tools")
        elif auth_type == "api_key":
            issues.append("API key auth is weak — consider OAuth2 or mTLS")

        return {
            "server_id": server_id,
            "auth_type": auth_type,
            "issues": issues,
            "recommendation": "oauth2" if auth_type in ("none", "api_key") else "current_is_ok",
        }

    async def map_downstream_resources(
        self,
        server_id: str,
        server_name: str,
        endpoint: str,
        tools: list[str],
        resources: list[dict[str, Any]],
        owner: str = "",
    ) -> dict[str, Any]:
        """Map downstream resources for a server and register in the connection registry."""
        downstream = [
            DownstreamResource(
                resource_type=ResourceType(r.get("type", "api_endpoint")),
                resource_id=r.get("id", ""),
                access_level=r.get("access_level", "read"),
                sensitivity=r.get("sensitivity", "low"),
            )
            for r in resources
        ]

        conn = self._registry.register_connection(
            server_id=server_id,
            server_name=server_name,
            endpoint=endpoint,
            tools=tools,
            downstream_resources=downstream,
            owner=owner,
        )

        blast_radius = self._registry.map_blast_radius(server_id)
        return {
            "server_id": server_id,
            "connection_id": conn.id,
            "downstream_count": len(downstream),
            "risk_score": conn.risk_score,
            "blast_radius": blast_radius,
        }

    async def scan_dependencies(
        self,
        server_id: str,
        components: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Scan MCP server dependencies for supply chain vulnerabilities."""
        results: list[dict[str, Any]] = []
        for comp in components:
            record = self._supply_chain.register_component(
                server_id=server_id,
                component_type=MCPComponentType(comp.get("type", "npm_package")),
                name=comp.get("name", ""),
                version=comp.get("version", ""),
                source_url=comp.get("source_url", ""),
                integrity_hash=comp.get("integrity_hash", ""),
            )
            findings = self._supply_chain.scan_component(record.id)
            results.append(
                {
                    "component_id": record.id,
                    "name": record.name,
                    "version": record.version,
                    "scan_status": record.scan_status.value,
                    "vulnerabilities": len(findings),
                    "findings": [
                        {
                            "cve_id": f.cve_id,
                            "severity": f.severity.value,
                            "description": f.description,
                        }
                        for f in findings
                    ],
                }
            )
        return results

    async def generate_zero_trust_policy(
        self,
        server_id: str,
        require_oauth2: bool = True,
        require_tls: bool = True,
        require_cert_pinning: bool = False,
    ) -> dict[str, Any]:
        """Generate and enforce a zero-trust policy for a server."""
        policy = ZeroTrustPolicy(
            require_oauth2=require_oauth2,
            require_tls=require_tls,
            require_cert_pinning=require_cert_pinning,
        )
        result = self._zero_trust.enforce_policy(server_id, policy)

        # Add a gateway policy for the server
        server = self._zero_trust.get_server(server_id)
        if server:
            auth_req = AuthRequirement.OAUTH2 if require_oauth2 else AuthRequirement.NONE
            self._gateway.add_policy(
                server_pattern=server.endpoint or server_id,
                auth_requirement=auth_req,
            )

        return {
            "server_id": server_id,
            "policy_enforced": True,
            "enforcement_result": result,
        }

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
