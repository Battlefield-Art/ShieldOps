"""MCP Connection Registry — server inventory, blast-radius mapping, and God Key detection."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class ConnectionStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    BLOCKED = "blocked"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


class ConnectionRisk(StrEnum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResourceType(StrEnum):
    DATABASE = "database"
    FILE_SYSTEM = "file_system"
    API_ENDPOINT = "api_endpoint"
    CLOUD_SERVICE = "cloud_service"
    SAAS_APP = "saas_app"
    CODE_REPOSITORY = "code_repository"


# --- Models ---


class DownstreamResource(BaseModel):
    resource_type: ResourceType = ResourceType.API_ENDPOINT
    resource_id: str = ""
    access_level: str = "read"
    sensitivity: str = "low"


class MCPConnectionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    server_name: str = ""
    endpoint: str = ""
    agent_ids: list[str] = Field(default_factory=list)
    tools_exposed: list[str] = Field(default_factory=list)
    downstream_resources: list[DownstreamResource] = Field(default_factory=list)
    owner: str = ""
    risk_score: float = 0.0
    status: ConnectionStatus = ConnectionStatus.ACTIVE
    first_seen: float = Field(default_factory=time.time)
    last_active: float = Field(default_factory=time.time)


class MCPConnectionReport(BaseModel):
    total_connections: int = 0
    active_count: int = 0
    god_key_count: int = 0
    unowned_count: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_risk: dict[str, int] = Field(default_factory=dict)
    total_downstream_resources: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPConnectionRegistry:
    """Inventory of MCP server connections with blast-radius and God Key analysis."""

    def __init__(
        self,
        max_records: int = 200000,
        god_key_threshold: int = 5,
    ) -> None:
        self._max_records = max_records
        self._god_key_threshold = god_key_threshold
        self._connections: list[MCPConnectionRecord] = []
        logger.info(
            "mcp_connection_registry.initialized",
            max_records=max_records,
            god_key_threshold=god_key_threshold,
        )

    # -- connection registration ---------------------------------------------

    def register_connection(
        self,
        server_id: str,
        server_name: str = "",
        endpoint: str = "",
        agent_ids: list[str] | None = None,
        tools: list[str] | None = None,
        downstream_resources: list[DownstreamResource] | None = None,
        owner: str = "",
    ) -> MCPConnectionRecord:
        resources = downstream_resources or []
        risk_score = self._compute_risk_score(
            agent_count=len(agent_ids or []),
            tool_count=len(tools or []),
            downstream_count=len(resources),
            resources=resources,
        )
        record = MCPConnectionRecord(
            server_id=server_id,
            server_name=server_name,
            endpoint=endpoint,
            agent_ids=agent_ids or [],
            tools_exposed=tools or [],
            downstream_resources=resources,
            owner=owner,
            risk_score=risk_score,
        )
        self._connections.append(record)
        if len(self._connections) > self._max_records:
            self._connections = self._connections[-self._max_records :]
        logger.info(
            "mcp_connection_registry.connection_registered",
            server_id=server_id,
            server_name=server_name,
            risk_score=risk_score,
            downstream=len(resources),
        )
        return record

    def get_connection(self, server_id: str) -> MCPConnectionRecord | None:
        for c in self._connections:
            if c.server_id == server_id:
                return c
        return None

    def list_connections(
        self,
        status: ConnectionStatus | None = None,
        limit: int = 50,
    ) -> list[MCPConnectionRecord]:
        results = list(self._connections)
        if status is not None:
            results = [c for c in results if c.status == status]
        return results[-limit:]

    # -- blast-radius mapping ------------------------------------------------

    def map_blast_radius(self, server_id: str) -> dict[str, Any]:
        """Map all downstream resources reachable if a server is compromised."""
        conn = self.get_connection(server_id)
        if conn is None:
            return {"server_id": server_id, "status": "not_found"}

        resources_by_type: dict[str, list[str]] = {}
        sensitive_resources: list[str] = []
        for r in conn.downstream_resources:
            resources_by_type.setdefault(r.resource_type.value, []).append(r.resource_id)
            if r.sensitivity in ("high", "critical"):
                sensitive_resources.append(r.resource_id)

        # Include transitive exposure through agents
        exposed_agents = conn.agent_ids

        return {
            "server_id": server_id,
            "server_name": conn.server_name,
            "downstream_resource_count": len(conn.downstream_resources),
            "resources_by_type": resources_by_type,
            "sensitive_resources": sensitive_resources,
            "exposed_agents": exposed_agents,
            "tools_exposed": conn.tools_exposed,
            "risk_score": conn.risk_score,
            "blast_radius_category": self._categorize_blast_radius(conn),
        }

    # -- God Key detection ---------------------------------------------------

    def detect_god_keys(self, max_downstream: int | None = None) -> list[dict[str, Any]]:
        """Find servers with access to too many downstream resources (God Key risk)."""
        threshold = max_downstream or self._god_key_threshold
        god_keys: list[dict[str, Any]] = []
        for conn in self._connections:
            if len(conn.downstream_resources) >= threshold:
                sensitive = sum(
                    1 for r in conn.downstream_resources if r.sensitivity in ("high", "critical")
                )
                god_keys.append(
                    {
                        "server_id": conn.server_id,
                        "server_name": conn.server_name,
                        "downstream_count": len(conn.downstream_resources),
                        "sensitive_count": sensitive,
                        "tools_exposed": conn.tools_exposed,
                        "risk_score": conn.risk_score,
                        "owner": conn.owner,
                        "recommendation": "Apply least-privilege — split into scoped servers",
                    }
                )
        god_keys.sort(key=lambda x: x["downstream_count"], reverse=True)
        return god_keys

    # -- unowned servers -----------------------------------------------------

    def find_unowned_servers(self) -> list[dict[str, Any]]:
        """Find servers without an attributed owner."""
        unowned: list[dict[str, Any]] = []
        for conn in self._connections:
            if not conn.owner:
                unowned.append(
                    {
                        "server_id": conn.server_id,
                        "server_name": conn.server_name,
                        "endpoint": conn.endpoint,
                        "downstream_count": len(conn.downstream_resources),
                        "risk_score": conn.risk_score,
                        "recommendation": "Assign an owner for accountability",
                    }
                )
        return unowned

    # -- domain operations ---------------------------------------------------

    def rank_by_risk(self) -> list[dict[str, Any]]:
        """Rank all connections by risk score descending."""
        ranked = sorted(self._connections, key=lambda c: c.risk_score, reverse=True)
        return [
            {
                "server_id": c.server_id,
                "server_name": c.server_name,
                "risk_score": c.risk_score,
                "downstream_count": len(c.downstream_resources),
                "status": c.status.value,
            }
            for c in ranked
        ]

    def detect_inactive_connections(self, inactive_hours: int = 168) -> list[dict[str, Any]]:
        """Find connections inactive for more than N hours."""
        threshold = time.time() - (inactive_hours * 3600)
        inactive: list[dict[str, Any]] = []
        for c in self._connections:
            if c.last_active < threshold:
                inactive.append(
                    {
                        "server_id": c.server_id,
                        "server_name": c.server_name,
                        "last_active": c.last_active,
                        "hours_inactive": int((time.time() - c.last_active) / 3600),
                    }
                )
        inactive.sort(key=lambda x: x["hours_inactive"], reverse=True)
        return inactive

    def find_over_privileged_servers(self) -> list[dict[str, Any]]:
        """Find servers with write/admin access to sensitive resources."""
        over_priv: list[dict[str, Any]] = []
        for conn in self._connections:
            sensitive_write = [
                r
                for r in conn.downstream_resources
                if r.sensitivity in ("high", "critical") and r.access_level in ("write", "admin")
            ]
            if sensitive_write:
                over_priv.append(
                    {
                        "server_id": conn.server_id,
                        "server_name": conn.server_name,
                        "sensitive_write_count": len(sensitive_write),
                        "resources": [r.resource_id for r in sensitive_write],
                        "recommendation": "Downgrade to read-only or remove sensitive access",
                    }
                )
        return over_priv

    # -- report / stats ------------------------------------------------------

    def generate_connection_report(self) -> MCPConnectionReport:
        by_status: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        for c in self._connections:
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1
            risk_cat = self._risk_category(c.risk_score)
            by_risk[risk_cat] = by_risk.get(risk_cat, 0) + 1

        active = by_status.get(ConnectionStatus.ACTIVE.value, 0)
        god_keys = len(self.detect_god_keys())
        unowned = len(self.find_unowned_servers())
        total_downstream = sum(len(c.downstream_resources) for c in self._connections)

        recs: list[str] = []
        if god_keys > 0:
            recs.append(
                f"{god_keys} server(s) with God Key risk — "
                "apply least-privilege and split credentials"
            )
        if unowned > 0:
            recs.append(f"{unowned} server(s) without owner attribution")
        over_priv = len(self.find_over_privileged_servers())
        if over_priv > 0:
            recs.append(f"{over_priv} server(s) with over-privileged access to sensitive resources")
        if not recs:
            recs.append("MCP connection inventory is healthy")

        return MCPConnectionReport(
            total_connections=len(self._connections),
            active_count=active,
            god_key_count=god_keys,
            unowned_count=unowned,
            by_status=by_status,
            by_risk=by_risk,
            total_downstream_resources=total_downstream,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        status_dist: dict[str, int] = {}
        for c in self._connections:
            key = c.status.value
            status_dist[key] = status_dist.get(key, 0) + 1
        return {
            "total_connections": len(self._connections),
            "status_distribution": status_dist,
            "god_key_threshold": self._god_key_threshold,
            "unique_owners": len({c.owner for c in self._connections if c.owner}),
            "total_downstream": sum(len(c.downstream_resources) for c in self._connections),
        }

    def clear_data(self) -> dict[str, str]:
        self._connections.clear()
        logger.info("mcp_connection_registry.cleared")
        return {"status": "cleared"}

    # -- private helpers -----------------------------------------------------

    @staticmethod
    def _compute_risk_score(
        agent_count: int,
        tool_count: int,
        downstream_count: int,
        resources: list[DownstreamResource],
    ) -> float:
        """Compute a 0-100 risk score for a connection."""
        score = 0.0
        score += min(downstream_count * 8, 40)
        score += min(tool_count * 5, 20)
        score += min(agent_count * 3, 15)
        sensitive = sum(1 for r in resources if r.sensitivity in ("high", "critical"))
        score += min(sensitive * 10, 25)
        return min(round(score, 1), 100.0)

    @staticmethod
    def _categorize_blast_radius(conn: MCPConnectionRecord) -> str:
        n = len(conn.downstream_resources)
        if n >= 10:
            return "critical"
        if n >= 5:
            return "high"
        if n >= 2:
            return "medium"
        return "low"

    @staticmethod
    def _risk_category(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        if score >= 10:
            return "low"
        return "safe"
