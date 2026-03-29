"""Incident Similarity Engine Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SimilarityStage(StrEnum):
    INGEST_INCIDENT = "ingest_incident"
    EXTRACT_FEATURES = "extract_features"
    COMPUTE_SIMILARITY = "compute_similarity"
    RANK_MATCHES = "rank_matches"
    RECOMMEND = "recommend"
    REPORT = "report"


class FeatureType(StrEnum):
    TTP = "ttp"
    IOC = "ioc"
    TIMELINE = "timeline"
    ASSET = "asset"
    ACTOR = "actor"
    IMPACT = "impact"


class MatchQuality(StrEnum):
    EXACT = "exact"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    NONE = "none"


class IncidentSimilarityEngineState(BaseModel):
    request_id: str = ""
    stage: SimilarityStage = SimilarityStage.INGEST_INCIDENT
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
