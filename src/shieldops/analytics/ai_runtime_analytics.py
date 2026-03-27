"""AI Runtime Analytics — metrics and guardrail coverage."""

from __future__ import annotations

import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class RuntimeMetric(StrEnum):
    LATENCY = "latency"
    TOKEN_USAGE = "token_usage"  # noqa: S105
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    COST_PER_CALL = "cost_per_call"


class ThreatFrequency(StrEnum):
    RARE = "rare"
    OCCASIONAL = "occasional"
    FREQUENT = "frequent"
    PERSISTENT = "persistent"
    EPIDEMIC = "epidemic"


class GuardrailHitRate(StrEnum):
    ZERO = "zero"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    SATURATED = "saturated"


# --- Models ---


class AIRuntimeRecord(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    agent_id: str = ""
    metric: RuntimeMetric = RuntimeMetric.LATENCY
    threat_freq: ThreatFrequency = ThreatFrequency.RARE
    guardrail_hit: GuardrailHitRate = GuardrailHitRate.ZERO
    value: float = 0.0
    model_id: str = ""
    environment: str = ""
    created_at: float = Field(default_factory=time.time)


class AIRuntimeAnalysis(BaseModel):
    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    agent_id: str = ""
    avg_latency: float = 0.0
    avg_token_usage: float = 0.0
    threat_trend: str = ""
    guardrail_coverage_pct: float = 0.0
    analyzed_at: float = Field(default_factory=time.time)


class AIRuntimeReport(BaseModel):
    total_records: int = 0
    unique_agents: int = 0
    avg_latency: float = 0.0
    threat_events: int = 0
    guardrail_triggers: int = 0
    by_metric: dict[str, int] = Field(
        default_factory=dict,
    )
    by_threat_freq: dict[str, int] = Field(
        default_factory=dict,
    )
    recommendations: list[str] = Field(
        default_factory=list,
    )
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


class AIRuntimeAnalyticsEngine:
    """Track AI runtime metrics and threats."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        self._records: list[AIRuntimeRecord] = []
        logger.info(
            "ai_runtime_analytics.initialized",
            max_records=max_records,
        )

    def _evict(self) -> None:
        if len(self._records) > self._max_records:
            self._records = self._records[-self._max_records :]

    def add_record(
        self,
        **kwargs: Any,
    ) -> AIRuntimeRecord:
        record = AIRuntimeRecord(**kwargs)
        self._records.append(record)
        self._evict()
        logger.info(
            "ai_runtime_analytics.record_added",
            record_id=record.id,
        )
        return record

    def process(
        self,
        key: str,
    ) -> AIRuntimeAnalysis:
        matches = [r for r in self._records if r.agent_id == key]
        if not matches:
            return AIRuntimeAnalysis(agent_id=key)
        latencies = [r.value for r in matches if r.metric == RuntimeMetric.LATENCY]
        tokens = [r.value for r in matches if r.metric == RuntimeMetric.TOKEN_USAGE]
        avg_lat = (
            round(
                sum(latencies) / len(latencies),
                4,
            )
            if latencies
            else 0.0
        )
        avg_tok = (
            round(
                sum(tokens) / len(tokens),
                4,
            )
            if tokens
            else 0.0
        )
        guarded = sum(1 for r in matches if r.guardrail_hit != GuardrailHitRate.ZERO)
        cov = (
            round(
                guarded / len(matches) * 100,
                2,
            )
            if matches
            else 0.0
        )
        return AIRuntimeAnalysis(
            agent_id=key,
            avg_latency=avg_lat,
            avg_token_usage=avg_tok,
            guardrail_coverage_pct=cov,
        )

    def generate_report(self) -> AIRuntimeReport:
        by_metric: dict[str, int] = {}
        by_threat: dict[str, int] = {}
        agents: set[str] = set()
        threat_events = 0
        guardrail_triggers = 0
        latencies: list[float] = []
        for r in self._records:
            m = r.metric.value
            by_metric[m] = by_metric.get(m, 0) + 1
            tf = r.threat_freq.value
            by_threat[tf] = by_threat.get(tf, 0) + 1
            agents.add(r.agent_id)
            if r.threat_freq != ThreatFrequency.RARE:
                threat_events += 1
            if r.guardrail_hit != GuardrailHitRate.ZERO:
                guardrail_triggers += 1
            if r.metric == RuntimeMetric.LATENCY:
                latencies.append(r.value)
        avg_lat = (
            round(
                sum(latencies) / len(latencies),
                4,
            )
            if latencies
            else 0.0
        )
        recs: list[str] = []
        if threat_events > 0:
            recs.append(f"{threat_events} threat event(s)")
        if avg_lat > 5.0:
            recs.append("Avg latency exceeds 5s")
        if not recs:
            recs.append("AI runtime healthy")
        return AIRuntimeReport(
            total_records=len(self._records),
            unique_agents=len(agents),
            avg_latency=avg_lat,
            threat_events=threat_events,
            guardrail_triggers=guardrail_triggers,
            by_metric=by_metric,
            by_threat_freq=by_threat,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_records": len(self._records),
            "max_records": self._max_records,
            "unique_agents": len({r.agent_id for r in self._records}),
        }

    def clear_data(self) -> dict[str, str]:
        self._records.clear()
        logger.info("ai_runtime_analytics.cleared")
        return {"status": "cleared"}

    # -- domain methods --

    def track_runtime_metrics(
        self,
        agent_id: str,
        metric: RuntimeMetric,
        value: float,
    ) -> dict[str, Any]:
        """Track a runtime metric."""
        record = self.add_record(
            agent_id=agent_id,
            metric=metric,
            value=value,
        )
        return {
            "record_id": record.id,
            "agent_id": agent_id,
            "metric": metric.value,
            "value": value,
        }

    def analyze_threat_trends(
        self,
    ) -> dict[str, Any]:
        """Analyze threat frequency trends."""
        by_freq: dict[str, int] = {}
        for r in self._records:
            if r.threat_freq != ThreatFrequency.RARE:
                f = r.threat_freq.value
                by_freq[f] = by_freq.get(f, 0) + 1
        total = sum(by_freq.values())
        return {
            "total_threats": total,
            "by_frequency": by_freq,
            "trend": ("increasing" if total > 10 else "stable"),
        }

    def measure_guardrail_coverage(
        self,
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """Measure guardrail hit coverage."""
        subset = self._records
        if agent_id is not None:
            subset = [r for r in subset if r.agent_id == agent_id]
        total = len(subset)
        if total == 0:
            return {"total": 0, "coverage_pct": 0.0}
        hits = sum(1 for r in subset if r.guardrail_hit != GuardrailHitRate.ZERO)
        return {
            "total": total,
            "hits": hits,
            "coverage_pct": round(
                hits / total * 100,
                2,
            ),
        }
