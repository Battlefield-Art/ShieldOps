"""Kill Chain Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AnalysisStage(StrEnum):
    INGEST_ALERTS = "ingest_alerts"
    MAP_KILL_CHAIN = "map_kill_chain"
    IDENTIFY_GAPS = "identify_gaps"
    CORRELATE_STAGES = "correlate_stages"
    RECOMMEND = "recommend"
    REPORT = "report"


class KillChainPhase(StrEnum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class CoverageLevel(StrEnum):
    FULL = "full"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    NONE = "none"


class KillChainAnalyzerState(BaseModel):
    request_id: str = ""
    stage: AnalysisStage = AnalysisStage.INGEST_ALERTS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
