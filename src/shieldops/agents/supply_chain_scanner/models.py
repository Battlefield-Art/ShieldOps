"""Supply Chain Scanner Agent — Pydantic state and data models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class ScanStage(StrEnum):
    INVENTORY_AI_ASSETS = "inventory_ai_assets"
    SCAN_MODEL_REGISTRIES = "scan_model_registries"
    SCAN_RAG_SOURCES = "scan_rag_sources"
    SCAN_PROMPT_TEMPLATES = "scan_prompt_templates"
    SCAN_TOOL_DEFINITIONS = "scan_tool_definitions"
    REPORT = "report"


class AssetType(StrEnum):
    MODEL_WEIGHT = "model_weight"
    RAG_DOCUMENT = "rag_document"
    PROMPT_TEMPLATE = "prompt_template"
    TOOL_DEFINITION = "tool_definition"
    TRAINING_DATASET = "training_dataset"
    EMBEDDING_MODEL = "embedding_model"


class ThreatType(StrEnum):
    DATA_POISONING = "data_poisoning"
    MODEL_BACKDOOR = "model_backdoor"
    PROMPT_INJECTION_TEMPLATE = "prompt_injection_template"
    TOOL_HIJACKING = "tool_hijacking"
    DEPENDENCY_TAMPERING = "dependency_tampering"


class AIAsset(BaseModel):
    """An AI component discovered during inventory."""

    id: str = ""
    name: str = ""
    asset_type: AssetType = AssetType.MODEL_WEIGHT
    version: str = ""
    source: str = ""
    checksum: str = ""
    verified: bool = False
    risk_score: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RegistryScan(BaseModel):
    """Result of scanning a model registry entry."""

    id: str = ""
    model_name: str = ""
    registry: str = ""
    checksum_match: bool = True
    provenance_verified: bool = False
    signature_valid: bool = False
    threat_type: ThreatType | None = None
    severity: str = "low"
    detail: str = ""


class RAGSourceScan(BaseModel):
    """Result of scanning a RAG data source."""

    id: str = ""
    source_name: str = ""
    source_uri: str = ""
    document_count: int = 0
    poisoned_count: int = 0
    adversarial_embeddings: int = 0
    threat_type: ThreatType | None = None
    severity: str = "low"
    detail: str = ""


class TemplateAudit(BaseModel):
    """Result of auditing a prompt template."""

    id: str = ""
    template_name: str = ""
    template_hash: str = ""
    injection_vulnerable: bool = False
    unescaped_variables: list[str] = Field(default_factory=list)
    threat_type: ThreatType | None = None
    severity: str = "low"
    detail: str = ""


class ToolDefinitionAudit(BaseModel):
    """Result of auditing an agent tool definition."""

    id: str = ""
    tool_name: str = ""
    tool_endpoint: str = ""
    hijack_risk: bool = False
    unauthorized_scope: bool = False
    exfiltration_capable: bool = False
    threat_type: ThreatType | None = None
    severity: str = "low"
    detail: str = ""


class ReasoningStep(BaseModel):
    """A single step in the agent reasoning chain."""

    step: str = ""
    detail: str = ""
    confidence: float = 0.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class SupplyChainScannerState(BaseModel):
    """Main state for the Supply Chain Scanner graph."""

    # Input
    request_id: str = ""
    stage: ScanStage = ScanStage.INVENTORY_AI_ASSETS
    tenant_id: str = ""

    # Asset inventory
    ai_assets: list[dict[str, Any]] = Field(default_factory=list)

    # Scan findings
    registry_findings: list[dict[str, Any]] = Field(default_factory=list)
    rag_findings: list[dict[str, Any]] = Field(default_factory=list)
    template_findings: list[dict[str, Any]] = Field(default_factory=list)
    tool_findings: list[dict[str, Any]] = Field(default_factory=list)

    # Aggregates
    total_threats: int = 0
    supply_chain_score: float = 0.0
    stats: dict[str, Any] = Field(default_factory=dict)

    # Workflow
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    session_duration_ms: float = 0.0
    error: str = ""
