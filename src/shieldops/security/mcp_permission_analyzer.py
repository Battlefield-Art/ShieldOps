"""MCP Permission Analyzer — analyze and recommend MCP server permission scoping."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class PermissionLevel(StrEnum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"
    EXECUTE = "execute"
    NONE = "none"


class AnalysisOutcome(StrEnum):
    OPTIMAL = "optimal"
    OVER_PRIVILEGED = "over_privileged"
    UNDER_PRIVILEGED = "under_privileged"
    UNUSED = "unused"
    RISKY = "risky"


class PermissionSource(StrEnum):
    CONFIG = "config"
    RUNTIME = "runtime"
    INHERITED = "inherited"
    DEFAULT = "default"


# --- Models ---


class PermissionRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    tool_name: str = ""
    level: PermissionLevel = PermissionLevel.READ
    source: PermissionSource = PermissionSource.CONFIG
    used: bool = False
    usage_count: int = 0
    last_used: float = 0.0
    created_at: float = Field(default_factory=time.time)


class PermissionAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    server_id: str = ""
    total_permissions: int = 0
    over_privileged: int = 0
    unused: int = 0
    recommendations: list[str] = Field(default_factory=list)
    outcome: AnalysisOutcome = AnalysisOutcome.OPTIMAL
    analyzed_at: float = Field(default_factory=time.time)


class PermissionAnalyzerReport(BaseModel):
    total_permissions: int = 0
    total_analyses: int = 0
    over_privileged_count: int = 0
    unused_count: int = 0
    by_level: dict[str, int] = Field(default_factory=dict)
    by_outcome: dict[str, int] = Field(default_factory=dict)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class MCPPermissionAnalyzer:
    """Analyze and recommend permission scoping for MCP servers."""

    def __init__(self, max_records: int = 200000) -> None:
        self._max_records = max_records
        self._permissions: list[PermissionRecord] = []
        self._analyses: list[PermissionAnalysis] = []
        logger.info("mcp_permission_analyzer.initialized", max_records=max_records)

    def record_permission(
        self,
        server_id: str,
        tool_name: str,
        level: PermissionLevel = PermissionLevel.READ,
        source: PermissionSource = PermissionSource.CONFIG,
        used: bool = False,
        usage_count: int = 0,
    ) -> PermissionRecord:
        record = PermissionRecord(
            server_id=server_id,
            tool_name=tool_name,
            level=level,
            source=source,
            used=used,
            usage_count=usage_count,
            last_used=time.time() if used else 0.0,
        )
        self._permissions.append(record)
        if len(self._permissions) > self._max_records:
            self._permissions = self._permissions[-self._max_records :]
        return record

    def analyze_server(self, server_id: str) -> PermissionAnalysis:
        perms = [p for p in self._permissions if p.server_id == server_id]
        over_priv = 0
        unused = 0
        recs: list[str] = []
        for p in perms:
            if p.level == PermissionLevel.ADMIN and p.usage_count == 0:
                over_priv += 1
                recs.append(f"Downgrade '{p.tool_name}' from admin — never used")
            elif not p.used and p.level != PermissionLevel.NONE:
                unused += 1
                recs.append(f"Remove unused permission for '{p.tool_name}'")
        if over_priv > 0:
            outcome = AnalysisOutcome.OVER_PRIVILEGED
        elif unused > len(perms) * 0.5 and perms:
            outcome = AnalysisOutcome.UNUSED
        else:
            outcome = AnalysisOutcome.OPTIMAL
        analysis = PermissionAnalysis(
            server_id=server_id,
            total_permissions=len(perms),
            over_privileged=over_priv,
            unused=unused,
            recommendations=recs,
            outcome=outcome,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        return analysis

    def detect_excessive_permissions(self) -> list[PermissionRecord]:
        return [
            p for p in self._permissions if p.level == PermissionLevel.ADMIN and p.usage_count == 0
        ]

    def detect_unused_permissions(self, stale_days: int = 30) -> list[PermissionRecord]:
        cutoff = time.time() - stale_days * 86400
        return [p for p in self._permissions if not p.used and p.created_at < cutoff]

    def generate_report(self) -> PermissionAnalyzerReport:
        by_level: dict[str, int] = {}
        by_outcome: dict[str, int] = {}
        for p in self._permissions:
            by_level[p.level.value] = by_level.get(p.level.value, 0) + 1
        for a in self._analyses:
            by_outcome[a.outcome.value] = by_outcome.get(a.outcome.value, 0) + 1
        over_priv = len(self.detect_excessive_permissions())
        unused = sum(1 for p in self._permissions if not p.used)
        recs: list[str] = []
        if over_priv > 0:
            recs.append(f"{over_priv} excessive admin permissions should be downgraded")
        if unused > 0:
            recs.append(f"{unused} unused permissions should be reviewed")
        if not recs:
            recs.append("Permission scoping is optimal")
        return PermissionAnalyzerReport(
            total_permissions=len(self._permissions),
            total_analyses=len(self._analyses),
            over_privileged_count=over_priv,
            unused_count=unused,
            by_level=by_level,
            by_outcome=by_outcome,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_permissions": len(self._permissions),
            "total_analyses": len(self._analyses),
            "unique_servers": len({p.server_id for p in self._permissions}),
            "unique_tools": len({p.tool_name for p in self._permissions}),
        }

    def clear_data(self) -> dict[str, str]:
        self._permissions.clear()
        self._analyses.clear()
        return {"status": "cleared"}
