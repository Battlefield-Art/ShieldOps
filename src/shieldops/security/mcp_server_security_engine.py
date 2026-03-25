"""MCP Server Security Engine — track MCP server security posture and God Key risk."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class MCPAuthType(StrEnum):
    OAUTH2 = "oauth2"
    API_KEY = "api_key"
    MTLS = "mtls"
    NONE = "none"
    CUSTOM = "custom"


class GodKeyStatus(StrEnum):
    DETECTED = "detected"
    MITIGATED = "mitigated"
    NONE = "none"
    INVESTIGATING = "investigating"
    ACCEPTED_RISK = "accepted_risk"


class MCPRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SECURE = "secure"


# --- Models ---


class MCPServerSecurityRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    mcp_auth_type: MCPAuthType = MCPAuthType.OAUTH2
    god_key_status: GodKeyStatus = GodKeyStatus.NONE
    mcp_risk_level: MCPRiskLevel = MCPRiskLevel.LOW
    tools_exposed: int = 0
    downstream_systems: int = 0
    tls_enabled: bool = True
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MCPServerSecurityAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    mcp_auth_type: MCPAuthType = MCPAuthType.OAUTH2
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MCPServerSecurityReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_mcp_auth_type: dict[str, int] = Field(default_factory=dict)
    by_god_key_status: dict[str, int] = Field(default_factory=dict)
    by_mcp_risk_level: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPServerSecurityEngine:
    """Track MCP server security posture, auth coverage, and God Key risk."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 70.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[MCPServerSecurityRecord] = []
        self._analyses: list[MCPServerSecurityAnalysis] = []
        logger.info(
            "mcp_server_security_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        server_id: str,
        mcp_auth_type: MCPAuthType = MCPAuthType.OAUTH2,
        god_key_status: GodKeyStatus = GodKeyStatus.NONE,
        mcp_risk_level: MCPRiskLevel = MCPRiskLevel.LOW,
        tools_exposed: int = 0,
        downstream_systems: int = 0,
        tls_enabled: bool = True,
        service: str = "",
        team: str = "",
    ) -> MCPServerSecurityRecord:
        record = MCPServerSecurityRecord(
            server_id=server_id,
            mcp_auth_type=mcp_auth_type,
            god_key_status=god_key_status,
            mcp_risk_level=mcp_risk_level,
            tools_exposed=tools_exposed,
            downstream_systems=downstream_systems,
            tls_enabled=tls_enabled,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mcp_server_security_engine.record_added",
            record_id=record.id,
            server_id=server_id,
            mcp_auth_type=mcp_auth_type.value,
            god_key_status=god_key_status.value,
        )
        return record

    def get_record(self, record_id: str) -> MCPServerSecurityRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        mcp_auth_type: MCPAuthType | None = None,
        god_key_status: GodKeyStatus | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MCPServerSecurityRecord]:
        results = list(self._records)
        if mcp_auth_type is not None:
            results = [r for r in results if r.mcp_auth_type == mcp_auth_type]
        if god_key_status is not None:
            results = [r for r in results if r.god_key_status == god_key_status]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        server_id: str,
        mcp_auth_type: MCPAuthType = MCPAuthType.OAUTH2,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MCPServerSecurityAnalysis:
        analysis = MCPServerSecurityAnalysis(
            server_id=server_id,
            mcp_auth_type=mcp_auth_type,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "mcp_server_security_engine.analysis_added",
            server_id=server_id,
            mcp_auth_type=mcp_auth_type.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_auth_coverage(self) -> list[dict[str, Any]]:
        """Analyze authentication coverage across MCP servers."""
        auth_data: dict[str, list[int]] = {}
        for r in self._records:
            auth_data.setdefault(r.mcp_auth_type.value, []).append(r.tools_exposed)
        results: list[dict[str, Any]] = []
        for auth, tools_list in auth_data.items():
            no_tls = sum(
                1 for r in self._records if r.mcp_auth_type.value == auth and not r.tls_enabled
            )
            results.append(
                {
                    "mcp_auth_type": auth,
                    "server_count": len(tools_list),
                    "total_tools_exposed": sum(tools_list),
                    "avg_tools_per_server": round(sum(tools_list) / len(tools_list), 2)
                    if tools_list
                    else 0.0,
                    "no_tls_count": no_tls,
                }
            )
        return sorted(results, key=lambda x: x["server_count"], reverse=True)

    def identify_god_keys(self) -> list[dict[str, Any]]:
        """Identify MCP servers with detected God Key risk."""
        god_keys: list[dict[str, Any]] = []
        for r in self._records:
            if r.god_key_status in (
                GodKeyStatus.DETECTED,
                GodKeyStatus.INVESTIGATING,
            ):
                god_keys.append(
                    {
                        "record_id": r.id,
                        "server_id": r.server_id,
                        "god_key_status": r.god_key_status.value,
                        "mcp_risk_level": r.mcp_risk_level.value,
                        "tools_exposed": r.tools_exposed,
                        "downstream_systems": r.downstream_systems,
                        "tls_enabled": r.tls_enabled,
                        "service": r.service,
                    }
                )
        return sorted(god_keys, key=lambda x: x["downstream_systems"], reverse=True)

    def detect_security_trends(self) -> list[dict[str, Any]]:
        """Detect security posture trends across MCP servers."""
        risk_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            svc = r.service or "unknown"
            risk_data.setdefault(svc, {})
            rl = r.mcp_risk_level.value
            risk_data[svc][rl] = risk_data[svc].get(rl, 0) + 1
        results: list[dict[str, Any]] = []
        for svc, risks in risk_data.items():
            critical_high = risks.get("critical", 0) + risks.get("high", 0)
            results.append(
                {
                    "service": svc,
                    "risk_distribution": risks,
                    "critical_high_count": critical_high,
                    "total_servers": sum(risks.values()),
                }
            )
        return sorted(results, key=lambda x: x["critical_high_count"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> MCPServerSecurityReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.mcp_auth_type.value] = by_e1.get(r.mcp_auth_type.value, 0) + 1
            by_e2[r.god_key_status.value] = by_e2.get(r.god_key_status.value, 0) + 1
            by_e3[r.mcp_risk_level.value] = by_e3.get(r.mcp_risk_level.value, 0) + 1
        risk_scores = {
            MCPRiskLevel.CRITICAL: 10,
            MCPRiskLevel.HIGH: 30,
            MCPRiskLevel.MEDIUM: 60,
            MCPRiskLevel.LOW: 80,
            MCPRiskLevel.SECURE: 100,
        }
        scores = [risk_scores.get(r.mcp_risk_level, 50) for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for s in scores if s < self._threshold)
        god_keys = self.identify_god_keys()
        top_gaps = [o["server_id"] for o in god_keys[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} server(s) below risk threshold ({self._threshold})")
        if god_keys:
            recs.append(f"{len(god_keys)} server(s) with God Key risk detected")
        if not recs:
            recs.append("MCP Server Security Engine is healthy")
        return MCPServerSecurityReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_mcp_auth_type=by_e1,
            by_god_key_status=by_e2,
            by_mcp_risk_level=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("mcp_server_security_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.mcp_auth_type.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "risk_threshold": self._threshold,
            "mcp_auth_type_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
