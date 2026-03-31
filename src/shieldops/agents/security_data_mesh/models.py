"""Security Data Mesh Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SDMStage(StrEnum):
    DISCOVER_DOMAINS = "discover_domains"
    MAP_DATA_PRODUCTS = "map_data_products"
    ASSESS_QUALITY = "assess_quality"
    FEDERATE_QUERIES = "federate_queries"
    GENERATE_INSIGHTS = "generate_insights"
    REPORT = "report"


class DomainStatus(StrEnum):
    ACTIVE = "active"
    DEGRADED = "degraded"
    OFFLINE = "offline"
    ONBOARDING = "onboarding"
    DEPRECATED = "deprecated"


class DataQualityGrade(StrEnum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"
    FAILING = "failing"


class SecurityDomain(BaseModel):
    """A security data domain in the mesh."""

    id: str = ""
    name: str = ""
    owner: str = ""
    status: DomainStatus = DomainStatus.ACTIVE
    data_product_count: int = 0
    freshness_minutes: int = 0
    consumers: int = 0
    tags: list[str] = Field(default_factory=list)


class DataProduct(BaseModel):
    """A data product within a security domain."""

    id: str = ""
    domain_id: str = ""
    name: str = ""
    schema_version: str = "1.0"
    record_count: int = 0
    freshness_minutes: int = 0
    quality_score: float = 0.0
    sla_met: bool = True
    consumers: list[str] = Field(default_factory=list)


class QualityAssessment(BaseModel):
    """Quality assessment for a data product."""

    id: str = ""
    product_id: str = ""
    grade: DataQualityGrade = DataQualityGrade.GOOD
    completeness: float = 0.0
    accuracy: float = 0.0
    timeliness: float = 0.0
    consistency: float = 0.0
    issues: list[str] = Field(default_factory=list)


class FederatedQuery(BaseModel):
    """A federated query across security domains."""

    id: str = ""
    query: str = ""
    domains_queried: list[str] = Field(default_factory=list)
    records_returned: int = 0
    latency_ms: float = 0.0
    status: str = "success"


class MeshInsight(BaseModel):
    """An insight generated from cross-domain analysis."""

    id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "medium"
    domains_involved: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    actionable: bool = True


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SecurityDataMeshState(BaseModel):
    """Main state for the Security Data Mesh agent."""

    request_id: str = ""
    tenant_id: str = ""
    stage: SDMStage = SDMStage.DISCOVER_DOMAINS

    security_domains: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    data_products: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    quality_assessments: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    federated_queries: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    mesh_insights: list[dict[str, Any]] = Field(
        default_factory=list,
    )

    report: str = ""
    total_domains: int = 0
    total_products: int = 0

    reasoning_chain: list[ReasoningStep] = Field(
        default_factory=list,
    )
    error: str = ""
