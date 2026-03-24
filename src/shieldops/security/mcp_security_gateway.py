"""MCP Security Gateway — request-level policy enforcement for MCP server traffic."""

from __future__ import annotations

import re
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class GatewayAction(StrEnum):
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    REQUIRE_AUTH = "require_auth"
    AUDIT_ONLY = "audit_only"
    QUARANTINE = "quarantine"


class AuthRequirement(StrEnum):
    NONE = "none"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    MTLS = "mtls"
    JWT = "jwt"
    CUSTOM = "custom"


class MCPTransport(StrEnum):
    STDIO = "stdio"
    HTTP_SSE = "http_sse"
    WEBSOCKET = "websocket"
    GRPC = "grpc"


# --- Models ---


class GatewayEventRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str = ""
    server_endpoint: str = ""
    agent_id: str = ""
    tool_invoked: str = ""
    action_taken: GatewayAction = GatewayAction.ALLOW
    auth_status: str = "unknown"
    latency_ms: float = 0.0
    data_bytes: int = 0
    timestamp: float = Field(default_factory=time.time)


class GatewayPolicy(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_pattern: str = ""
    allowed_agents: list[str] = Field(default_factory=list)
    auth_requirement: AuthRequirement = AuthRequirement.OAUTH2
    rate_limit_per_minute: int = 60
    max_data_bytes: int = 10_485_760
    allowed_tools: list[str] = Field(default_factory=list)
    blocked_tools: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class GatewayReport(BaseModel):
    total_events: int = 0
    blocked_count: int = 0
    allowed_count: int = 0
    rate_limited_count: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_server: dict[str, int] = Field(default_factory=dict)
    policy_count: int = 0
    anomalies_detected: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPSecurityGateway:
    """Request-level gateway enforcing policies on MCP server traffic."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._events: list[GatewayEventRecord] = []
        self._policies: list[GatewayPolicy] = []
        logger.info("mcp_security_gateway.initialized", max_records=max_records)

    # -- policy management ---------------------------------------------------

    def add_policy(
        self,
        server_pattern: str,
        allowed_agents: list[str] | None = None,
        auth_requirement: AuthRequirement = AuthRequirement.OAUTH2,
        rate_limit_per_minute: int = 60,
        max_data_bytes: int = 10_485_760,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
    ) -> GatewayPolicy:
        policy = GatewayPolicy(
            server_pattern=server_pattern,
            allowed_agents=allowed_agents or [],
            auth_requirement=auth_requirement,
            rate_limit_per_minute=rate_limit_per_minute,
            max_data_bytes=max_data_bytes,
            allowed_tools=allowed_tools or [],
            blocked_tools=blocked_tools or [],
        )
        self._policies.append(policy)
        logger.info(
            "mcp_security_gateway.policy_added",
            policy_id=policy.id,
            server_pattern=server_pattern,
            auth_requirement=auth_requirement.value,
        )
        return policy

    def _match_policy(self, server_endpoint: str) -> GatewayPolicy | None:
        for policy in self._policies:
            if re.search(policy.server_pattern, server_endpoint):
                return policy
        return None

    # -- request evaluation --------------------------------------------------

    def evaluate_request(
        self,
        server_endpoint: str,
        agent_id: str,
        tool_name: str,
        auth_token: str | None = None,
        data_size: int = 0,
    ) -> dict[str, Any]:
        """Evaluate a single MCP request against gateway policies."""
        reasons: list[str] = []
        policy = self._match_policy(server_endpoint)

        if policy is None:
            reasons.append("no_policy_matched_default_audit")
            return {"action": GatewayAction.AUDIT_ONLY, "reasons": reasons}

        # Auth check
        if policy.auth_requirement != AuthRequirement.NONE and not auth_token:
            reasons.append(f"auth_required_{policy.auth_requirement.value}")
            return {"action": GatewayAction.REQUIRE_AUTH, "reasons": reasons}

        # Agent check
        if policy.allowed_agents and agent_id not in policy.allowed_agents:
            reasons.append(f"agent_{agent_id}_not_in_allowlist")
            return {"action": GatewayAction.BLOCK, "reasons": reasons}

        # Tool check
        if policy.blocked_tools and tool_name in policy.blocked_tools:
            reasons.append(f"tool_{tool_name}_blocked_by_policy")
            return {"action": GatewayAction.BLOCK, "reasons": reasons}

        if policy.allowed_tools and tool_name not in policy.allowed_tools:
            reasons.append(f"tool_{tool_name}_not_in_allowlist")
            return {"action": GatewayAction.BLOCK, "reasons": reasons}

        # Data size check
        if data_size > policy.max_data_bytes:
            reasons.append(f"data_size_{data_size}_exceeds_limit_{policy.max_data_bytes}")
            return {"action": GatewayAction.BLOCK, "reasons": reasons}

        # Rate limit check
        if not self.check_rate_limit(server_endpoint, agent_id):
            reasons.append("rate_limit_exceeded")
            return {"action": GatewayAction.RATE_LIMIT, "reasons": reasons}

        reasons.append("all_checks_passed")
        return {"action": GatewayAction.ALLOW, "reasons": reasons}

    # -- event recording -----------------------------------------------------

    def record_event(
        self,
        server_endpoint: str,
        agent_id: str,
        tool_name: str,
        action: GatewayAction = GatewayAction.ALLOW,
        auth_status: str = "unknown",
        latency_ms: float = 0.0,
        data_bytes: int = 0,
    ) -> GatewayEventRecord:
        record = GatewayEventRecord(
            request_id=str(uuid.uuid4()),
            server_endpoint=server_endpoint,
            agent_id=agent_id,
            tool_invoked=tool_name,
            action_taken=action,
            auth_status=auth_status,
            latency_ms=latency_ms,
            data_bytes=data_bytes,
        )
        self._events.append(record)
        if len(self._events) > self._max_records:
            self._events = self._events[-self._max_records :]
        logger.info(
            "mcp_security_gateway.event_recorded",
            request_id=record.request_id,
            server_endpoint=server_endpoint,
            action=action.value,
        )
        return record

    # -- rate limiting -------------------------------------------------------

    def check_rate_limit(self, server_endpoint: str, agent_id: str) -> bool:
        """Return True if agent is within rate limit for the given server."""
        policy = self._match_policy(server_endpoint)
        if policy is None:
            return True
        window_start = time.time() - 60.0
        count = sum(
            1
            for e in self._events
            if e.server_endpoint == server_endpoint
            and e.agent_id == agent_id
            and e.timestamp >= window_start
        )
        return count < policy.rate_limit_per_minute

    # -- anomaly detection ---------------------------------------------------

    def detect_anomalous_access(
        self, server_endpoint: str, window_minutes: int = 15
    ) -> list[dict[str, Any]]:
        """Detect anomalous access patterns for a server endpoint."""
        window_start = time.time() - (window_minutes * 60)
        recent = [
            e
            for e in self._events
            if e.server_endpoint == server_endpoint and e.timestamp >= window_start
        ]
        anomalies: list[dict[str, Any]] = []

        # Detect burst access
        if len(recent) > 100:
            anomalies.append(
                {
                    "type": "burst_access",
                    "count": len(recent),
                    "window_minutes": window_minutes,
                    "severity": "high",
                }
            )

        # Detect multiple agent access
        unique_agents = {e.agent_id for e in recent}
        if len(unique_agents) > 10:
            anomalies.append(
                {
                    "type": "many_agents",
                    "unique_agents": len(unique_agents),
                    "severity": "medium",
                }
            )

        # Detect large data transfers
        total_bytes = sum(e.data_bytes for e in recent)
        if total_bytes > 100_000_000:
            anomalies.append(
                {
                    "type": "large_data_transfer",
                    "total_bytes": total_bytes,
                    "severity": "high",
                }
            )

        return anomalies

    # -- report / stats ------------------------------------------------------

    def generate_gateway_report(self) -> GatewayReport:
        by_action: dict[str, int] = {}
        by_server: dict[str, int] = {}
        for e in self._events:
            by_action[e.action_taken.value] = by_action.get(e.action_taken.value, 0) + 1
            by_server[e.server_endpoint] = by_server.get(e.server_endpoint, 0) + 1

        blocked = by_action.get(GatewayAction.BLOCK.value, 0)
        allowed = by_action.get(GatewayAction.ALLOW.value, 0)
        rate_limited = by_action.get(GatewayAction.RATE_LIMIT.value, 0)

        recs: list[str] = []
        if blocked > len(self._events) * 0.2:
            recs.append("High block rate detected — review policies for over-restriction")
        if rate_limited > 0:
            recs.append(f"{rate_limited} requests rate-limited — consider adjusting limits")

        servers_without_policy = [s for s in by_server if self._match_policy(s) is None]
        if servers_without_policy:
            recs.append(f"{len(servers_without_policy)} server(s) without gateway policy")
        if not recs:
            recs.append("MCP gateway operating normally")

        anomaly_count = sum(len(self.detect_anomalous_access(s)) for s in set(by_server.keys()))

        return GatewayReport(
            total_events=len(self._events),
            blocked_count=blocked,
            allowed_count=allowed,
            rate_limited_count=rate_limited,
            by_action=by_action,
            by_server=by_server,
            policy_count=len(self._policies),
            anomalies_detected=anomaly_count,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        action_dist: dict[str, int] = {}
        for e in self._events:
            key = e.action_taken.value
            action_dist[key] = action_dist.get(key, 0) + 1
        return {
            "total_events": len(self._events),
            "policy_count": len(self._policies),
            "action_distribution": action_dist,
            "unique_servers": len({e.server_endpoint for e in self._events}),
            "unique_agents": len({e.agent_id for e in self._events}),
        }

    def clear_data(self) -> dict[str, str]:
        self._events.clear()
        self._policies.clear()
        logger.info("mcp_security_gateway.cleared")
        return {"status": "cleared"}
