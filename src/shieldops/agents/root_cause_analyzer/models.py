"""Root Cause Analyzer Agent models."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class RCAStage(StrEnum):
    COLLECT_SIGNALS = "collect_signals"
    BUILD_GRAPH = "build_graph"
    TRACE_CAUSALITY = "trace_causality"
    RANK_CAUSES = "rank_causes"
    RECOMMEND_FIXES = "recommend_fixes"
    REPORT = "report"


class SignalSource(StrEnum):
    METRICS = "metrics"
    LOGS = "logs"
    TRACES = "traces"
    EVENTS = "events"
    ALERTS = "alerts"
    CHANGES = "changes"


class CausalityConfidence(StrEnum):
    DEFINITIVE = "definitive"
    PROBABLE = "probable"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"
    UNKNOWN = "unknown"


class RootCauseAnalyzerState(BaseModel):
    request_id: str = ""
    stage: RCAStage = RCAStage.COLLECT_SIGNALS
    tenant_id: str = ""
    findings: list[dict[str, Any]] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    reasoning_chain: list[str] = Field(default_factory=list)
    current_step: str = ""
    session_start: float = 0.0
    error: str = ""
