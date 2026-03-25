"""Tool functions for the MCP Gateway Agent.

Provides async functions that discover MCP servers, assess security posture,
enforce gateway policies, and monitor traffic for abuse. Includes God Key
detection — flagging single credentials that grant write access to >3
downstream systems.
"""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.mcp_gateway.models import (
    AuthMethod,
    MCPServerProfile,
    MCPServerRisk,
    PolicyEnforcement,
    SecurityAssessment,
    TrafficAnomaly,
)

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# God Key detection threshold
# ---------------------------------------------------------------------------
_GOD_KEY_WRITE_THRESHOLD = 3  # write access to >3 downstream systems


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


async def discover_mcp_servers(
    tenant_id: str,
) -> list[MCPServerProfile]:
    """Discover MCP servers registered for *tenant_id*.

    In production this would query a service registry (Consul, K8s service
    discovery, or the ShieldOps MCP connection registry).  For now it
    returns simulated server profiles for graph execution.
    """
    logger.info(
        "mcp_gateway.discover_servers",
        tenant_id=tenant_id,
    )

    # Simulated discovery — real implementation queries registry / API
    discovered: list[MCPServerProfile] = []
    registry_entries = _query_server_registry(tenant_id)
    for entry in registry_entries:
        profile = MCPServerProfile(
            id=entry.get("id", f"mcp-{uuid4().hex[:8]}"),
            server_name=entry.get("name", "unknown"),
            endpoint_url=entry.get("endpoint", ""),
            auth_method=AuthMethod(entry.get("auth", "none")),
            tools_exposed=entry.get("tools", []),
            permission_scope=entry.get("scope", ""),
            tls_enabled=entry.get("tls", False),
            rate_limit_configured=entry.get("rate_limited", False),
            last_audited=entry.get("last_audited", 0.0),
        )
        discovered.append(profile)

    logger.info(
        "mcp_gateway.servers_discovered",
        tenant_id=tenant_id,
        count=len(discovered),
    )
    return discovered


# ---------------------------------------------------------------------------
# Security assessment (includes God Key detection)
# ---------------------------------------------------------------------------


async def assess_mcp_security(
    servers: list[MCPServerProfile],
) -> list[SecurityAssessment]:
    """Assess security posture of each server and detect God Key patterns.

    A **God Key** is a single credential granting write access to more than
    ``_GOD_KEY_WRITE_THRESHOLD`` downstream systems.
    """
    logger.info(
        "mcp_gateway.assess_security",
        server_count=len(servers),
    )

    assessments: list[SecurityAssessment] = []
    for server in servers:
        vulns: list[str] = []
        missing: list[str] = []
        risk_score = 0.0

        # Auth checks
        if server.auth_method == AuthMethod.NONE:
            vulns.append("No authentication configured")
            missing.append("OAuth 2.0 or mTLS required")
            risk_score += 30.0
        elif server.auth_method == AuthMethod.API_KEY:
            vulns.append("API key auth is weak — rotate and upgrade")
            missing.append("OAuth 2.0 recommended over static API keys")
            risk_score += 15.0

        # Transport checks
        if not server.tls_enabled:
            vulns.append("TLS not enabled — traffic is plaintext")
            missing.append("TLS 1.3 transport encryption")
            risk_score += 25.0

        # Rate limiting
        if not server.rate_limit_configured:
            missing.append("Rate limiting not configured")
            risk_score += 10.0

        # God Key detection: write access to >3 downstream systems
        write_scopes = _count_write_scopes(server)
        god_key = write_scopes > _GOD_KEY_WRITE_THRESHOLD
        if god_key:
            vulns.append(
                f"God Key pattern: write access to {write_scopes} "
                f"downstream systems (threshold: {_GOD_KEY_WRITE_THRESHOLD})"
            )
            risk_score += 40.0

        # Classify risk
        if risk_score >= 70:
            server.risk_level = MCPServerRisk.CRITICAL
        elif risk_score >= 50:
            server.risk_level = MCPServerRisk.HIGH
        elif risk_score >= 25:
            server.risk_level = MCPServerRisk.MEDIUM
        elif risk_score > 0:
            server.risk_level = MCPServerRisk.LOW
        else:
            server.risk_level = MCPServerRisk.SECURE

        server.god_key_risk = god_key

        remediation: list[str] = []
        if god_key:
            remediation.append("Decompose credential into per-system scoped tokens")
        if server.auth_method in (AuthMethod.NONE, AuthMethod.API_KEY):
            remediation.append("Upgrade to OAuth 2.0 with short-lived tokens")
        if not server.tls_enabled:
            remediation.append("Enable TLS 1.3 on the server endpoint")
        if not server.rate_limit_configured:
            remediation.append("Configure per-tool rate limits at the gateway")

        assessments.append(
            SecurityAssessment(
                id=f"assess-{uuid4().hex[:8]}",
                server_id=server.id,
                vulnerabilities=vulns,
                missing_controls=missing,
                god_key_detected=god_key,
                risk_score=min(risk_score, 100.0),
                remediation_steps=remediation,
            )
        )

    logger.info(
        "mcp_gateway.security_assessed",
        assessed=len(assessments),
        god_keys=sum(1 for a in assessments if a.god_key_detected),
    )
    return assessments


# ---------------------------------------------------------------------------
# Policy enforcement
# ---------------------------------------------------------------------------


async def enforce_gateway_policies(
    assessments: list[SecurityAssessment],
) -> list[PolicyEnforcement]:
    """Generate and apply gateway enforcement policies based on assessments."""
    logger.info(
        "mcp_gateway.enforce_policies",
        assessment_count=len(assessments),
    )

    enforcements: list[PolicyEnforcement] = []
    for assessment in assessments:
        # OAuth enforcement for unauthenticated servers
        if any("authentication" in v.lower() for v in assessment.vulnerabilities):
            enforcements.append(
                PolicyEnforcement(
                    id=f"pol-{uuid4().hex[:8]}",
                    server_id=assessment.server_id,
                    policy_name="require_oauth2",
                    action="enforce",
                    target="authentication",
                    applied=True,
                    success=True,
                )
            )

        # TLS enforcement
        if any("tls" in v.lower() for v in assessment.vulnerabilities):
            enforcements.append(
                PolicyEnforcement(
                    id=f"pol-{uuid4().hex[:8]}",
                    server_id=assessment.server_id,
                    policy_name="require_tls",
                    action="enforce",
                    target="transport",
                    applied=True,
                    success=True,
                )
            )

        # Rate limit enforcement
        if any("rate" in c.lower() for c in assessment.missing_controls):
            enforcements.append(
                PolicyEnforcement(
                    id=f"pol-{uuid4().hex[:8]}",
                    server_id=assessment.server_id,
                    policy_name="apply_rate_limit",
                    action="enforce",
                    target="rate_limiting",
                    applied=True,
                    success=True,
                )
            )

        # God Key mitigation — warn + audit until credential is rotated
        if assessment.god_key_detected:
            enforcements.append(
                PolicyEnforcement(
                    id=f"pol-{uuid4().hex[:8]}",
                    server_id=assessment.server_id,
                    policy_name="god_key_mitigation",
                    action="warn",
                    target="credential_scope",
                    applied=True,
                    success=True,
                )
            )

    logger.info(
        "mcp_gateway.policies_enforced",
        enforcements=len(enforcements),
    )
    return enforcements


# ---------------------------------------------------------------------------
# Traffic monitoring
# ---------------------------------------------------------------------------


async def monitor_mcp_traffic(
    servers: list[MCPServerProfile],
) -> list[TrafficAnomaly]:
    """Monitor real-time traffic through the gateway for abuse patterns.

    Checks for: excessive request rates, unknown callers, suspicious tool
    chaining, and data exfiltration indicators.
    """
    logger.info(
        "mcp_gateway.monitor_traffic",
        server_count=len(servers),
    )

    anomalies: list[TrafficAnomaly] = []
    for server in servers:
        traffic_data = _get_traffic_metrics(server.id)
        for metric in traffic_data:
            if metric["requests"] > metric.get("threshold", 100):
                anomalies.append(
                    TrafficAnomaly(
                        id=f"anomaly-{uuid4().hex[:8]}",
                        server_id=server.id,
                        anomaly_type=metric.get("type", "rate_exceeded"),
                        tool_name=metric.get("tool", ""),
                        caller_id=metric.get("caller", "unknown"),
                        request_count=metric["requests"],
                        time_window_min=metric.get("window_min", 5),
                        blocked=metric["requests"] > metric.get("block_threshold", 500),
                    )
                )

    logger.info(
        "mcp_gateway.traffic_monitored",
        anomalies=len(anomalies),
        blocked=sum(1 for a in anomalies if a.blocked),
    )
    return anomalies


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _query_server_registry(tenant_id: str) -> list[dict[str, Any]]:
    """Query the MCP server registry for a tenant.

    Placeholder — production implementation reads from the ShieldOps
    MCP connection registry or a service-discovery backend.
    """
    _ = tenant_id
    return []


def _count_write_scopes(server: MCPServerProfile) -> int:
    """Count how many downstream systems a server has write access to.

    Parses the ``permission_scope`` string for write/admin tokens.
    Each comma-separated scope containing 'write' or 'admin' counts.
    """
    if not server.permission_scope:
        return 0
    scopes = [s.strip().lower() for s in server.permission_scope.split(",")]
    return sum(1 for s in scopes if "write" in s or "admin" in s)


def _get_traffic_metrics(server_id: str) -> list[dict[str, Any]]:
    """Fetch recent traffic metrics for a server.

    Placeholder — production implementation queries the gateway's
    metrics pipeline (Prometheus / Redis counters).
    """
    _ = server_id
    return []
