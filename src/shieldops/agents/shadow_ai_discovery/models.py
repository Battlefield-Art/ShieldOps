"""Shadow AI Discovery Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class DiscoveryStage(StrEnum):
    SCAN_NETWORK = "scan_network"
    ANALYZE_TRAFFIC = "analyze_traffic"
    IDENTIFY_AGENTS = "identify_agents"
    CLASSIFY_RISK = "classify_risk"
    RECOMMEND_GOVERNANCE = "recommend_governance"
    REPORT = "report"


class AIAssetType(StrEnum):
    LLM_API_CLIENT = "llm_api_client"
    MCP_SERVER = "mcp_server"
    RAG_PIPELINE = "rag_pipeline"
    FINE_TUNED_MODEL = "fine_tuned_model"
    AI_AGENT = "ai_agent"
    EMBEDDING_SERVICE = "embedding_service"
    VECTOR_DATABASE = "vector_database"


class GovernanceStatus(StrEnum):
    MANAGED = "managed"
    UNMANAGED = "unmanaged"
    SHADOW = "shadow"
    ROGUE = "rogue"
    PENDING_REVIEW = "pending_review"
    EXEMPTED = "exempted"


class ShadowAIAsset(BaseModel):
    """A discovered AI asset that may or may not be under governance."""

    id: str = ""
    asset_type: AIAssetType = AIAssetType.LLM_API_CLIENT
    name: str = ""
    endpoint_url: str = ""
    owner: str = ""
    department: str = ""
    governance_status: GovernanceStatus = GovernanceStatus.UNMANAGED
    model_provider: str = ""
    estimated_monthly_cost: float = 0.0
    data_sensitivity: str = "unknown"
    first_seen: float = 0.0
    last_seen: float = 0.0
    risk_score: float = 0.0


class TrafficPattern(BaseModel):
    """A detected network traffic pattern potentially related to AI services."""

    id: str = ""
    source_ip: str = ""
    destination: str = ""
    protocol: str = "https"
    requests_per_day: int = 0
    avg_payload_kb: float = 0.0
    tls_version: str = "1.3"
    is_llm_traffic: bool = False


class GovernanceRecommendation(BaseModel):
    """A recommended governance action for a discovered shadow AI asset."""

    id: str = ""
    asset_id: str = ""
    action: str = ""
    priority: str = "medium"
    description: str = ""
    estimated_effort: str = ""
    auto_enforceable: bool = False


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ShadowAIDiscoveryState(BaseModel):
    """Main state for the Shadow AI Discovery graph."""

    # Input
    request_id: str = ""
    stage: DiscoveryStage = DiscoveryStage.SCAN_NETWORK
    tenant_id: str = ""
    scan_scope: list[str] = Field(default_factory=list)

    # Discovery
    traffic_patterns: list[dict[str, Any]] = Field(default_factory=list)
    discovered_assets: list[dict[str, Any]] = Field(default_factory=list)
    governance_recommendations: list[dict[str, Any]] = Field(default_factory=list)

    # Stats
    stats: dict[str, Any] = Field(default_factory=dict)

    # Reasoning
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
