"""Rogue Agent Tracker Engine — track and monitor unauthorized AI agent activity."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AgentOrigin(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    THIRD_PARTY = "third_party"
    UNKNOWN = "unknown"
    COMPROMISED = "compromised"


class AgentBehavior(StrEnum):
    NORMAL = "normal"
    ANOMALOUS = "anomalous"
    MALICIOUS = "malicious"
    DORMANT = "dormant"
    ESCALATING = "escalating"


class ContainmentStatus(StrEnum):
    ACTIVE = "active"
    CONTAINED = "contained"
    BLOCKED = "blocked"
    QUARANTINED = "quarantined"
    TERMINATED = "terminated"


# --- Models ---


class RogueAgentRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    agent_origin: AgentOrigin = AgentOrigin.UNKNOWN
    agent_behavior: AgentBehavior = AgentBehavior.NORMAL
    containment_status: ContainmentStatus = ContainmentStatus.ACTIVE
    tool_calls_per_hour: int = 0
    data_accessed_mb: float = 0.0
    risk_score: float = 0.0
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class RogueAgentAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    agent_origin: AgentOrigin = AgentOrigin.UNKNOWN
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class RogueAgentReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_risk_score: float = 0.0
    by_agent_origin: dict[str, int] = Field(default_factory=dict)
    by_agent_behavior: dict[str, int] = Field(default_factory=dict)
    by_containment_status: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class RogueAgentTrackerEngine:
    """Track and monitor unauthorized AI agent activity."""

    def __init__(
        self,
        max_records: int = 200000,
        risk_threshold: float = 75.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = risk_threshold
        self._records: list[RogueAgentRecord] = []
        self._analyses: list[RogueAgentAnalysis] = []
        logger.info(
            "rogue_agent_tracker_engine.initialized",
            max_records=max_records,
            risk_threshold=risk_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        agent_id: str,
        agent_origin: AgentOrigin = AgentOrigin.UNKNOWN,
        agent_behavior: AgentBehavior = AgentBehavior.NORMAL,
        containment_status: ContainmentStatus = ContainmentStatus.ACTIVE,
        tool_calls_per_hour: int = 0,
        data_accessed_mb: float = 0.0,
        risk_score: float = 0.0,
        service: str = "",
        team: str = "",
    ) -> RogueAgentRecord:
        record = RogueAgentRecord(
            agent_id=agent_id,
            agent_origin=agent_origin,
            agent_behavior=agent_behavior,
            containment_status=containment_status,
            tool_calls_per_hour=tool_calls_per_hour,
            data_accessed_mb=data_accessed_mb,
            risk_score=risk_score,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "rogue_agent_tracker_engine.record_added",
            record_id=record.id,
            agent_id=agent_id,
            agent_origin=agent_origin.value,
            agent_behavior=agent_behavior.value,
        )
        return record

    def get_record(self, record_id: str) -> RogueAgentRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        agent_origin: AgentOrigin | None = None,
        agent_behavior: AgentBehavior | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[RogueAgentRecord]:
        results = list(self._records)
        if agent_origin is not None:
            results = [r for r in results if r.agent_origin == agent_origin]
        if agent_behavior is not None:
            results = [r for r in results if r.agent_behavior == agent_behavior]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        agent_id: str,
        agent_origin: AgentOrigin = AgentOrigin.UNKNOWN,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> RogueAgentAnalysis:
        analysis = RogueAgentAnalysis(
            agent_id=agent_id,
            agent_origin=agent_origin,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "rogue_agent_tracker_engine.analysis_added",
            agent_id=agent_id,
            agent_origin=agent_origin.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_agent_behavior_distribution(self) -> dict[str, Any]:
        """Analyze agent behavior distribution by origin."""
        origin_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.agent_origin.value
            origin_data.setdefault(key, {})
            beh = r.agent_behavior.value
            origin_data[key][beh] = origin_data[key].get(beh, 0) + 1
        result: dict[str, Any] = {}
        for origin, behaviors in origin_data.items():
            total = sum(behaviors.values())
            malicious_ct = behaviors.get("malicious", 0) + behaviors.get("escalating", 0)
            risk_pct = round(malicious_ct / total * 100, 2) if total else 0.0
            result[origin] = {
                "total": total,
                "behaviors": behaviors,
                "risk_percentage": risk_pct,
                "above_threshold": risk_pct > self._threshold,
            }
        return result

    def identify_rogue_agents(self) -> list[dict[str, Any]]:
        """Identify agents with malicious or escalating behavior."""
        rogue: list[dict[str, Any]] = []
        for r in self._records:
            if r.agent_behavior in (
                AgentBehavior.MALICIOUS,
                AgentBehavior.ESCALATING,
            ):
                rogue.append(
                    {
                        "record_id": r.id,
                        "agent_id": r.agent_id,
                        "agent_origin": r.agent_origin.value,
                        "agent_behavior": r.agent_behavior.value,
                        "containment_status": r.containment_status.value,
                        "tool_calls_per_hour": r.tool_calls_per_hour,
                        "data_accessed_mb": r.data_accessed_mb,
                        "risk_score": r.risk_score,
                        "service": r.service,
                    }
                )
        return sorted(rogue, key=lambda x: x["risk_score"], reverse=True)

    def detect_behavior_trends(self) -> list[dict[str, Any]]:
        """Detect trends in agent behavior over time."""
        buckets: dict[str, list[RogueAgentRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            malicious_ct = sum(
                1
                for r in records
                if r.agent_behavior in (AgentBehavior.MALICIOUS, AgentBehavior.ESCALATING)
            )
            avg_risk = (
                round(sum(r.risk_score for r in records) / len(records), 2) if records else 0.0
            )
            trends.append(
                {
                    "date": day,
                    "total_agents": len(records),
                    "malicious_or_escalating": malicious_ct,
                    "avg_risk_score": avg_risk,
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> RogueAgentReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.agent_origin.value] = by_e1.get(r.agent_origin.value, 0) + 1
            by_e2[r.agent_behavior.value] = by_e2.get(r.agent_behavior.value, 0) + 1
            by_e3[r.containment_status.value] = by_e3.get(r.containment_status.value, 0) + 1
        scores = [r.risk_score for r in self._records]
        avg_risk = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_count = sum(1 for r in self._records if r.risk_score >= self._threshold)
        gap_list = self.identify_rogue_agents()
        top_gaps = [o["agent_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} agent(s) above risk threshold ({self._threshold})")
        if not recs:
            recs.append("Rogue Agent Tracker Engine is healthy")
        return RogueAgentReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_risk_score=avg_risk,
            by_agent_origin=by_e1,
            by_agent_behavior=by_e2,
            by_containment_status=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("rogue_agent_tracker_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.agent_origin.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "agent_origin_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
