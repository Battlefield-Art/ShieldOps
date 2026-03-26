"""AISurfaceScannerEngine — Scan AI attack surfaces including MCP, LLM, and RAG exposures."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class AISurface(StrEnum):
    MCP_SERVER = "mcp_server"
    LLM_ENDPOINT = "llm_endpoint"
    RAG_PIPELINE = "rag_pipeline"
    MODEL_REGISTRY = "model_registry"
    AGENT_API = "agent_api"


class AIExposure(StrEnum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    INTERNAL = "internal"
    UNREACHABLE = "unreachable"


class AIRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# --- Models ---


class AISurfaceRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ai_surface: AISurface = AISurface.MCP_SERVER
    ai_exposure: AIExposure = AIExposure.INTERNAL
    ai_risk_level: AIRiskLevel = AIRiskLevel.LOW
    score: float = 0.0
    endpoint_url: str = ""
    auth_required: bool = True
    service: str = ""
    team: str = ""
    created_at: float = Field(default_factory=time.time)


class AISurfaceAnalysis(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ai_surface: AISurface = AISurface.MCP_SERVER
    analysis_score: float = 0.0
    threshold: float = 0.0
    breached: bool = False
    description: str = ""
    created_at: float = Field(default_factory=time.time)


class AISurfaceReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    total_records: int = 0
    total_analyses: int = 0
    gap_count: int = 0
    avg_score: float = 0.0
    by_ai_surface: dict[str, int] = Field(default_factory=dict)
    by_ai_exposure: dict[str, int] = Field(default_factory=dict)
    by_ai_risk_level: dict[str, int] = Field(default_factory=dict)
    top_gaps: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)
    created_at: float = Field(default_factory=time.time)


# --- Engine ---


class AISurfaceScannerEngine:
    """Scan AI attack surfaces including MCP, LLM, and RAG exposures."""

    def __init__(
        self,
        max_records: int = 200000,
        threshold: float = 50.0,
    ) -> None:
        self._max_records = max_records
        self._threshold = threshold
        self._records: list[AISurfaceRecord] = []
        self._analyses: list[AISurfaceAnalysis] = []
        logger.info(
            "ai_surface_scanner_engine.initialized",
            max_records=max_records,
            threshold=threshold,
        )

    # -- record / get / list -----------------------------------

    def add_record(
        self,
        name: str,
        ai_surface: AISurface = AISurface.MCP_SERVER,
        ai_exposure: AIExposure = AIExposure.INTERNAL,
        ai_risk_level: AIRiskLevel = AIRiskLevel.LOW,
        score: float = 0.0,
        endpoint_url: str = "",
        auth_required: bool = True,
        service: str = "",
        team: str = "",
    ) -> AISurfaceRecord:
        record = AISurfaceRecord(
            name=name,
            ai_surface=ai_surface,
            ai_exposure=ai_exposure,
            ai_risk_level=ai_risk_level,
            score=score,
            endpoint_url=endpoint_url,
            auth_required=auth_required,
            service=service,
            team=team,
        )
        self._records.append(record)
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]
        logger.info(
            "ai_surface_scanner_engine.record_added",
            record_id=record.id,
            name=name,
            ai_surface=ai_surface.value,
            ai_exposure=ai_exposure.value,
        )
        return record

    def get_record(self, record_id: str) -> AISurfaceRecord | None:
        for r in self._records:
            if r.id == record_id:
                return r
        return None

    def list_records(
        self,
        ai_surface: AISurface | None = None,
        ai_exposure: AIExposure | None = None,
        team: str | None = None,
        limit: int = 50,
    ) -> list[AISurfaceRecord]:
        results = list(self._records)
        if ai_surface is not None:
            results = [r for r in results if r.ai_surface == ai_surface]
        if ai_exposure is not None:
            results = [r for r in results if r.ai_exposure == ai_exposure]
        if team is not None:
            results = [r for r in results if r.team == team]
        return results[-limit:]

    def add_analysis(
        self,
        name: str,
        ai_surface: AISurface = AISurface.MCP_SERVER,
        analysis_score: float = 0.0,
        threshold: float = 0.0,
        breached: bool = False,
        description: str = "",
    ) -> AISurfaceAnalysis:
        analysis = AISurfaceAnalysis(
            name=name,
            ai_surface=ai_surface,
            analysis_score=analysis_score,
            threshold=threshold,
            breached=breached,
            description=description,
        )
        self._analyses.append(analysis)
        if len(self._analyses) > self._max_records:
            self._analyses = self._analyses[-self._max_records :]
        logger.info(
            "ai_surface_scanner_engine.analysis_added",
            name=name,
            ai_surface=ai_surface.value,
            analysis_score=analysis_score,
        )
        return analysis

    # -- domain operations -------------------------------------

    def scan_mcp_endpoints(
        self,
    ) -> list[dict[str, Any]]:
        """Scan MCP server endpoints for exposure."""
        mcp_records = [r for r in self._records if r.ai_surface == AISurface.MCP_SERVER]
        results: list[dict[str, Any]] = []
        for r in mcp_records:
            risk = (
                "critical"
                if (r.ai_exposure == AIExposure.PUBLIC and not r.auth_required)
                else (
                    "high"
                    if r.ai_exposure == AIExposure.PUBLIC
                    else "medium"
                    if r.ai_exposure == AIExposure.AUTHENTICATED
                    else "low"
                )
            )
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "endpoint_url": r.endpoint_url,
                    "exposure": r.ai_exposure.value,
                    "auth_required": r.auth_required,
                    "risk": risk,
                    "service": r.service,
                    "recommendation": (
                        "Enforce authentication"
                        if not r.auth_required
                        else "Review access controls"
                        if r.ai_exposure == AIExposure.PUBLIC
                        else "Monitor access"
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: (
                0
                if x["risk"] == "critical"
                else (1 if x["risk"] == "high" else (2 if x["risk"] == "medium" else 3))
            ),
        )

    def detect_exposed_models(
        self,
    ) -> list[dict[str, Any]]:
        """Detect publicly exposed AI models."""
        exposed: list[dict[str, Any]] = []
        model_surfaces = {
            AISurface.LLM_ENDPOINT,
            AISurface.MODEL_REGISTRY,
        }
        for r in self._records:
            if r.ai_surface in model_surfaces and r.ai_exposure in (
                AIExposure.PUBLIC,
                AIExposure.AUTHENTICATED,
            ):
                exposed.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "surface": r.ai_surface.value,
                        "exposure": r.ai_exposure.value,
                        "risk_level": (r.ai_risk_level.value),
                        "endpoint_url": (r.endpoint_url),
                        "auth_required": (r.auth_required),
                        "service": r.service,
                    }
                )
        return sorted(
            exposed,
            key=lambda x: (
                0 if x["risk_level"] == "critical" else (1 if x["risk_level"] == "high" else 2)
            ),
        )

    def assess_rag_exposure(
        self,
    ) -> list[dict[str, Any]]:
        """Assess RAG pipeline exposure and data leak risk."""
        rag_records = [r for r in self._records if r.ai_surface == AISurface.RAG_PIPELINE]
        results: list[dict[str, Any]] = []
        for r in rag_records:
            data_leak_risk = (
                "critical"
                if r.ai_exposure == AIExposure.PUBLIC
                else (
                    "high"
                    if not r.auth_required
                    else ("medium" if r.ai_exposure == AIExposure.AUTHENTICATED else "low")
                )
            )
            results.append(
                {
                    "record_id": r.id,
                    "name": r.name,
                    "exposure": r.ai_exposure.value,
                    "data_leak_risk": data_leak_risk,
                    "auth_required": r.auth_required,
                    "score": r.score,
                    "service": r.service,
                    "recommendation": (
                        "Restrict RAG pipeline access"
                        if data_leak_risk in ("critical", "high")
                        else "Monitor data access"
                    ),
                }
            )
        return sorted(
            results,
            key=lambda x: (
                0
                if x["data_leak_risk"] == "critical"
                else (1 if x["data_leak_risk"] == "high" else 2)
            ),
        )

    # -- standard methods --------------------------------------

    def analyze_distribution(
        self,
    ) -> dict[str, Any]:
        type_data: dict[str, list[float]] = {}
        for r in self._records:
            key = r.ai_surface.value
            type_data.setdefault(key, []).append(r.score)
        result: dict[str, Any] = {}
        for k, scores in type_data.items():
            result[k] = {
                "count": len(scores),
                "avg_score": round(sum(scores) / len(scores), 2),
            }
        return result

    def identify_gaps(
        self,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for r in self._records:
            if r.score < self._threshold:
                results.append(
                    {
                        "record_id": r.id,
                        "name": r.name,
                        "ai_surface": (r.ai_surface.value),
                        "score": r.score,
                        "service": r.service,
                        "team": r.team,
                    }
                )
        return sorted(results, key=lambda x: x["score"])

    def rank_by_score(
        self,
    ) -> list[dict[str, Any]]:
        svc_scores: dict[str, list[float]] = {}
        for r in self._records:
            svc_scores.setdefault(r.service, []).append(r.score)
        results: list[dict[str, Any]] = []
        for svc, scores in svc_scores.items():
            results.append(
                {
                    "service": svc,
                    "avg_score": round(sum(scores) / len(scores), 2),
                }
            )
        results.sort(key=lambda x: x["avg_score"])
        return results

    def process(self, key: str) -> dict[str, Any]:
        matched = [r for r in self._records if r.name == key or r.service == key]
        if not matched:
            return {
                "key": key,
                "status": "not_found",
                "count": 0,
            }
        scores = [r.score for r in matched]
        avg = round(sum(scores) / len(scores), 2)
        return {
            "key": key,
            "status": "processed",
            "count": len(matched),
            "avg_score": avg,
            "below_threshold": sum(1 for s in scores if s < self._threshold),
        }

    # -- report / stats ----------------------------------------

    def generate_report(self) -> AISurfaceReport:
        by_e1: dict[str, int] = {}
        by_e2: dict[str, int] = {}
        by_e3: dict[str, int] = {}
        for r in self._records:
            by_e1[r.ai_surface.value] = by_e1.get(r.ai_surface.value, 0) + 1
            by_e2[r.ai_exposure.value] = by_e2.get(r.ai_exposure.value, 0) + 1
            by_e3[r.ai_risk_level.value] = by_e3.get(r.ai_risk_level.value, 0) + 1
        gap_count = sum(1 for r in self._records if r.score < self._threshold)
        scores = [r.score for r in self._records]
        avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0
        gap_list = self.identify_gaps()
        top_gaps = [o["name"] for o in gap_list[:5]]
        recs: list[str] = []
        if self._records and gap_count > 0:
            recs.append(f"{gap_count} item(s) below threshold ({self._threshold})")
        if self._records and avg_score < self._threshold:
            recs.append(f"Avg score {avg_score} below threshold ({self._threshold})")
        if not recs:
            recs.append("AI Surface Scanner Engine is healthy")
        return AISurfaceReport(
            total_records=len(self._records),
            total_analyses=len(self._analyses),
            gap_count=gap_count,
            avg_score=avg_score,
            by_ai_surface=by_e1,
            by_ai_exposure=by_e2,
            by_ai_risk_level=by_e3,
            top_gaps=top_gaps,
            recommendations=recs,
        )

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        self._analyses.clear()
        logger.info("ai_surface_scanner_engine.cleared")
        return {"status": "cleared"}

    def get_stats(self) -> dict[str, Any]:
        e1_dist: dict[str, int] = {}
        for r in self._records:
            key = r.ai_surface.value
            e1_dist[key] = e1_dist.get(key, 0) + 1
        return {
            "total_records": len(self._records),
            "total_analyses": len(self._analyses),
            "threshold": self._threshold,
            "ai_surface_distribution": e1_dist,
            "unique_teams": len({r.team for r in self._records}),
            "unique_services": len({r.service for r in self._records}),
        }
