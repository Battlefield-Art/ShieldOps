"""Incident Cost Calculator Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class CalculationStage(StrEnum):
    GATHER_METRICS = "gather_metrics"
    COMPUTE_DIRECT = "compute_direct"
    COMPUTE_INDIRECT = "compute_indirect"
    PROJECT_LONG_TERM = "project_long_term"
    BENCHMARK = "benchmark"
    REPORT = "report"


class CostCategory(StrEnum):
    RESPONSE = "response"
    RECOVERY = "recovery"
    LEGAL = "legal"
    REGULATORY = "regulatory"
    REPUTATION = "reputation"
    BUSINESS_LOSS = "business_loss"


class CostConfidence(StrEnum):
    ACTUAL = "actual"
    ESTIMATED = "estimated"
    PROJECTED = "projected"
    UNKNOWN = "unknown"


class IncidentCostCalculatorState(BaseModel):
    request_id: str = ""
    stage: CalculationStage = CalculationStage.GATHER_METRICS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
