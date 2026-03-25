"""MCP Traffic Audit Engine — audit and analyze MCP tool call traffic."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class CallCategory(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"
    QUERY = "query"


class AuditResult(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    RATE_LIMITED = "rate_limited"
    FLAGGED = "flagged"
    LOGGED = "logged"


class CallerType(StrEnum):
    AI_AGENT = "ai_agent"
    SERVICE = "service"
    HUMAN = "human"
    UNKNOWN = "unknown"
    AUTOMATED = "automated"


# --- Models ---


class MCPTrafficAuditRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    call_id: str = ""
    call_category: CallCategory = CallCategory.READ
    audit_result: AuditResult = AuditResult.ALLOWED
    caller_type: CallerType = CallerType.AI_AGENT
    server_name: str = ""
    tool_name: str = ""
    latency_ms: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class MCPTrafficAuditAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    call_id: str = ""
    call_category: CallCategory = CallCategory.READ
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class MCPTrafficAuditReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_call_category: dict[str, int] = Field(default_factory=dict)
    by_audit_result: dict[str, int] = Field(default_factory=dict)
    by_caller_type: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPTrafficAuditEngine:
    """Audit and analyze MCP tool call traffic for anomalies."""

    def __init__(
        self,
        max_records: int = 200000,
        anomaly_threshold: float = 100.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = anomaly_threshold
        self._records: list[MCPTrafficAuditRecord] = []
        self._analyses: list[MCPTrafficAuditAnalysis] = []
        logger.info(
            "mcp_traffic_audit_engine.initialized",
            max_records=max_records,
            anomaly_threshold=anomaly_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        call_id: str,
        call_category: CallCategory = CallCategory.READ,
        audit_result: AuditResult = AuditResult.ALLOWED,
        caller_type: CallerType = CallerType.AI_AGENT,
        server_name: str = "",
        tool_name: str = "",
        latency_ms: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> MCPTrafficAuditRecord:
        record = MCPTrafficAuditRecord(
            call_id=call_id,
            call_category=call_category,
            audit_result=audit_result,
            caller_type=caller_type,
            server_name=server_name,
            tool_name=tool_name,
            latency_ms=latency_ms,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "mcp_traffic_audit_engine.record_added",
            record_id=record.id,
            call_id=call_id,
            call_category=call_category.value,
            audit_result=audit_result.value,
        )
        return record

    def get_record(self, record_id: str) -> MCPTrafficAuditRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        call_category: CallCategory | None = None,
        audit_result: AuditResult | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[MCPTrafficAuditRecord]:
        results = list(self._records)
        if call_category is not None:
            results = [r for r in results if r.call_category == call_category]
        if audit_result is not None:
            results = [r for r in results if r.audit_result == audit_result]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        call_id: str,
        call_category: CallCategory = CallCategory.READ,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> MCPTrafficAuditAnalysis:
        analysis = MCPTrafficAuditAnalysis(
            call_id=call_id,
            call_category=call_category,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "mcp_traffic_audit_engine.analysis_added",
            call_id=call_id,
            call_category=call_category.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_call_patterns(self) -> list[dict[str, Any]]:
        """Analyze call patterns by category and server."""
        server_data: dict[str, list[float]] = {}
        for r in self._records:
            server_data.setdefault(r.server_name or "unknown", []).append(r.latency_ms)
        results: list[dict[str, Any]] = []
        for srv, latencies in server_data.items():
            avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
            blocked = sum(
                1
                for r in self._records
                if (r.server_name or "unknown") == srv
                and r.audit_result in (AuditResult.BLOCKED, AuditResult.RATE_LIMITED)
            )
            results.append(
                {
                    "server_name": srv,
                    "call_count": len(latencies),
                    "avg_latency_ms": avg_latency,
                    "max_latency_ms": max(latencies) if latencies else 0.0,
                    "blocked_count": blocked,
                }
            )
        return sorted(results, key=lambda x: x["call_count"], reverse=True)

    def identify_suspicious_callers(self) -> list[dict[str, Any]]:
        """Identify callers with suspicious traffic patterns."""
        caller_stats: dict[str, dict[str, int]] = {}
        for r in self._records:
            ct = r.caller_type.value
            caller_stats.setdefault(ct, {"total": 0, "blocked": 0, "flagged": 0})
            caller_stats[ct]["total"] += 1
            if r.audit_result == AuditResult.BLOCKED:
                caller_stats[ct]["blocked"] += 1
            if r.audit_result == AuditResult.FLAGGED:
                caller_stats[ct]["flagged"] += 1
        results: list[dict[str, Any]] = []
        for ct, stats in caller_stats.items():
            suspicious_pct = (
                round((stats["blocked"] + stats["flagged"]) / stats["total"] * 100, 2)
                if stats["total"] > 0
                else 0.0
            )
            results.append(
                {
                    "caller_type": ct,
                    "total_calls": stats["total"],
                    "blocked_calls": stats["blocked"],
                    "flagged_calls": stats["flagged"],
                    "suspicious_pct": suspicious_pct,
                }
            )
        return sorted(results, key=lambda x: x["suspicious_pct"], reverse=True)

    def detect_traffic_trends(self) -> list[dict[str, Any]]:
        """Detect traffic volume and latency trends per tool."""
        tool_data: dict[str, list[float]] = {}
        for r in self._records:
            tool_data.setdefault(r.tool_name or "unknown", []).append(r.latency_ms)
        results: list[dict[str, Any]] = []
        for tool, latencies in tool_data.items():
            avg = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
            above_threshold = sum(1 for lat in latencies if lat > self._threshold)
            results.append(
                {
                    "tool_name": tool,
                    "call_count": len(latencies),
                    "avg_latency_ms": avg,
                    "above_threshold": above_threshold,
                    "anomaly_pct": round(above_threshold / len(latencies) * 100, 2)
                    if latencies
                    else 0.0,
                }
            )
        return sorted(results, key=lambda x: x["anomaly_pct"], reverse=True)

    # -- standard methods ---------------------------------------------------

    def generate_report(self) -> MCPTrafficAuditReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.call_category.value] = by_e1.get(r.call_category.value, 0) + 1
            by_e2[r.audit_result.value] = by_e2.get(r.audit_result.value, 0) + 1
            by_e3[r.caller_type.value] = by_e3.get(r.caller_type.value, 0) + 1
        latencies = [r.latency_ms for r in self._records]
        avg_score = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        gap_count = sum(1 for lat in latencies if lat > self._threshold)
        blocked = [
            r.call_id
            for r in self._records
            if r.audit_result in (AuditResult.BLOCKED, AuditResult.FLAGGED)
        ]
        top_gaps = blocked[:5]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} call(s) above latency threshold ({self._threshold}ms)")
        if by_e2.get("blocked", 0) > 0:
            recs.append(f"{by_e2['blocked']} call(s) were blocked")
        if not recs:
            recs.append("MCP Traffic Audit Engine is healthy")
        return MCPTrafficAuditReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_call_category=by_e1,
            by_audit_result=by_e2,
            by_caller_type=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("mcp_traffic_audit_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.call_category.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "anomaly_threshold": self._threshold,
            "call_category_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
