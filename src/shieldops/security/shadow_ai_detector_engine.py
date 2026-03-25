"""Shadow AI Detector Engine — track discovery of unmanaged AI assets."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AIAssetClass(StrEnum):
    LLM_CLIENT = "llm_client"
    MCP_SERVER = "mcp_server"
    RAG_PIPELINE = "rag_pipeline"
    FINE_TUNED_MODEL = "fine_tuned_model"
    VECTOR_DB = "vector_db"


class GovernanceState(StrEnum):
    MANAGED = "managed"
    UNMANAGED = "unmanaged"
    SHADOW = "shadow"
    ROGUE = "rogue"
    EXEMPTED = "exempted"


class DiscoveryMethod(StrEnum):
    TRAFFIC_ANALYSIS = "traffic_analysis"
    DNS_INSPECTION = "dns_inspection"
    API_FINGERPRINT = "api_fingerprint"
    CERTIFICATE_SCAN = "certificate_scan"
    LOG_ANALYSIS = "log_analysis"


# --- Models ---


class ShadowAIRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    ai_asset_class: AIAssetClass = AIAssetClass.LLM_CLIENT
    governance_state: GovernanceState = GovernanceState.UNMANAGED
    discovery_method: DiscoveryMethod = DiscoveryMethod.TRAFFIC_ANALYSIS
    endpoint: str = ""
    estimated_cost_monthly: float = 0.0
    data_sensitivity: str = ""
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class ShadowAIAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    asset_id: str = ""
    ai_asset_class: AIAssetClass = AIAssetClass.LLM_CLIENT
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class ShadowAIReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_cost_monthly: float = 0.0
    by_ai_asset_class: dict[str, int] = Field(default_factory=dict)
    by_governance_state: dict[str, int] = Field(default_factory=dict)
    by_discovery_method: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class ShadowAIDetectorEngine:
    """Track discovery of unmanaged AI assets across the enterprise."""

    def __init__(
        self,
        max_records: int = 200000,
        governance_threshold: float = 80.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = governance_threshold
        self._records: list[ShadowAIRecord] = []
        self._analyses: list[ShadowAIAnalysis] = []
        logger.info(
            "shadow_ai_detector_engine.initialized",
            max_records=max_records,
            governance_threshold=governance_threshold,
        )

    # -- record / get / list ------------------------------------------------

    def add_record(
        self,
        asset_id: str,
        ai_asset_class: AIAssetClass = AIAssetClass.LLM_CLIENT,
        governance_state: GovernanceState = GovernanceState.UNMANAGED,
        discovery_method: DiscoveryMethod = DiscoveryMethod.TRAFFIC_ANALYSIS,
        endpoint: str = "",
        estimated_cost_monthly: float = 0.0,
        data_sensitivity: str = "",
        service: str = "",
        team: str = "",
    ) -> ShadowAIRecord:
        record = ShadowAIRecord(
            asset_id=asset_id,
            ai_asset_class=ai_asset_class,
            governance_state=governance_state,
            discovery_method=discovery_method,
            endpoint=endpoint,
            estimated_cost_monthly=estimated_cost_monthly,
            data_sensitivity=data_sensitivity,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "shadow_ai_detector_engine.record_added",
            record_id=record.id,
            asset_id=asset_id,
            ai_asset_class=ai_asset_class.value,
            governance_state=governance_state.value,
        )
        return record

    def get_record(self, record_id: str) -> ShadowAIRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ai_asset_class: AIAssetClass | None = None,
        governance_state: GovernanceState | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[ShadowAIRecord]:
        results = list(self._records)
        if ai_asset_class is not None:
            results = [r for r in results if r.ai_asset_class == ai_asset_class]
        if governance_state is not None:
            results = [r for r in results if r.governance_state == governance_state]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        asset_id: str,
        ai_asset_class: AIAssetClass = AIAssetClass.LLM_CLIENT,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> ShadowAIAnalysis:
        analysis = ShadowAIAnalysis(
            asset_id=asset_id,
            ai_asset_class=ai_asset_class,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "shadow_ai_detector_engine.analysis_added",
            asset_id=asset_id,
            ai_asset_class=ai_asset_class.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations --------------------------------------------------

    def analyze_governance_coverage(self) -> dict[str, Any]:
        """Analyze governance coverage across AI asset classes."""
        class_data: dict[str, dict[str, int]] = {}
        for r in self._records:
            key = r.ai_asset_class.value
            class_data.setdefault(key, {})
            gs = r.governance_state.value
            class_data[key][gs] = class_data[key].get(gs, 0) + 1
        result: dict[str, Any] = {}
        for cls, states in class_data.items():
            total = sum(states.values())
            managed = states.get("managed", 0) + states.get("exempted", 0)
            coverage_pct = round(managed / total * 100, 2) if total else 0.0
            result[cls] = {
                "total": total,
                "states": states,
                "governance_coverage_pct": coverage_pct,
                "below_threshold": coverage_pct < self._threshold,
            }
        return result

    def identify_rogue_assets(self) -> list[dict[str, Any]]:
        """Identify rogue and shadow AI assets requiring immediate attention."""
        rogue: list[dict[str, Any]] = []
        for r in self._records:
            if r.governance_state in (GovernanceState.ROGUE, GovernanceState.SHADOW):
                rogue.append(
                    {
                        "record_id": r.id,
                        "asset_id": r.asset_id,
                        "ai_asset_class": r.ai_asset_class.value,
                        "governance_state": r.governance_state.value,
                        "discovery_method": r.discovery_method.value,
                        "endpoint": r.endpoint,
                        "estimated_cost_monthly": r.estimated_cost_monthly,
                        "data_sensitivity": r.data_sensitivity,
                        "service": r.service,
                    }
                )
        return sorted(rogue, key=lambda x: x["estimated_cost_monthly"], reverse=True)

    def detect_discovery_trends(self) -> list[dict[str, Any]]:
        """Detect trends in shadow AI discovery over time."""
        buckets: dict[str, list[ShadowAIRecord]] = {}
        for r in self._records:
            day = time.strftime("%Y-%m-%d", time.gmtime(r.created_at))
            buckets.setdefault(day, []).append(r)
        trends: list[dict[str, Any]] = []
        for day, records in sorted(buckets.items()):
            shadow_ct = sum(
                1
                for r in records
                if r.governance_state in (GovernanceState.SHADOW, GovernanceState.ROGUE)
            )
            total_cost = sum(r.estimated_cost_monthly for r in records)
            trends.append(
                {
                    "date": day,
                    "total_discoveries": len(records),
                    "shadow_or_rogue": shadow_ct,
                    "total_est_cost": round(total_cost, 2),
                }
            )
        return trends

    # -- report / stats -----------------------------------------------------

    def generate_report(self) -> ShadowAIReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.ai_asset_class.value] = by_e1.get(r.ai_asset_class.value, 0) + 1
            by_e2[r.governance_state.value] = by_e2.get(r.governance_state.value, 0) + 1
            by_e3[r.discovery_method.value] = by_e3.get(r.discovery_method.value, 0) + 1
        costs = [r.estimated_cost_monthly for r in self._records]
        avg_cost = round(sum(costs) / len(costs), 2) if costs else 0.0
        gap_count = sum(
            1
            for r in self._records
            if r.governance_state in (GovernanceState.SHADOW, GovernanceState.ROGUE)
        )
        gap_list = self.identify_rogue_assets()
        top_gaps = [o["asset_id"] for o in gap_list[:5]]
        recs: list[str] = []
        if gap_count > 0:
            recs.append(f"{gap_count} shadow/rogue AI asset(s) discovered")
        if not recs:
            recs.append("Shadow AI Detector Engine is healthy")
        return ShadowAIReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_cost_monthly=avg_cost,
            by_ai_asset_class=by_e1,
            by_governance_state=by_e2,
            by_discovery_method=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("shadow_ai_detector_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ai_asset_class.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "ai_asset_class_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
