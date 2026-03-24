"""Agent Behavioral Baseline — statistical baseline learning for AI agent behavior."""

from __future__ import annotations

import math
import time
import uuid
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# --- Enums ---


class BaselineStatus(StrEnum):
    LEARNING = "learning"
    ESTABLISHED = "established"
    STALE = "stale"
    ANOMALOUS = "anomalous"


class BaselineMetric(StrEnum):
    CALL_RATE = "call_rate"
    TOOL_DIVERSITY = "tool_diversity"
    DATA_VOLUME = "data_volume"
    TEMPORAL_PATTERN = "temporal_pattern"
    ERROR_RATE = "error_rate"
    RESPONSE_LATENCY = "response_latency"


class DeviationSeverity(StrEnum):
    NORMAL = "normal"
    MINOR = "minor"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    EXTREME = "extreme"


# --- Models ---


class BaselineRecord(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    metric: BaselineMetric = BaselineMetric.CALL_RATE
    mean: float = 0.0
    stddev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    sample_count: int = 0
    last_updated: float = Field(default_factory=time.time)


class DeviationEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    metric: BaselineMetric = BaselineMetric.CALL_RATE
    observed_value: float = 0.0
    expected_range: str = ""
    deviation_severity: DeviationSeverity = DeviationSeverity.NORMAL
    z_score: float = 0.0
    timestamp: float = Field(default_factory=time.time)


class BaselineReport(BaseModel):
    total_observations: int = 0
    total_baselines: int = 0
    total_deviations: int = 0
    by_metric: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    stale_baselines: int = 0
    recommendations: list[str] = Field(default_factory=list)
    generated_at: float = Field(default_factory=time.time)


# --- Engine ---


_MIN_SAMPLES_FOR_BASELINE = 10
_STALE_HOURS = 48


class AgentBehavioralBaseline:
    """Statistical baseline learning for AI agent behavior."""

    def __init__(
        self,
        max_records: int = 200000,
    ) -> None:
        self._max_records = max_records
        # Raw observations: {agent_id: {metric: [values]}}
        self._observations: dict[str, dict[str, list[float]]] = {}
        self._baselines: list[BaselineRecord] = []
        self._deviations: list[DeviationEvent] = []
        logger.info("agent_behavioral_baseline.initialized", max_records=max_records)

    # -- record --

    def record_observation(
        self,
        agent_id: str,
        metric: BaselineMetric,
        value: float,
    ) -> dict[str, Any]:
        """Feed a data point for baseline learning."""
        if agent_id not in self._observations:
            self._observations[agent_id] = {}
        metric_key = metric.value
        if metric_key not in self._observations[agent_id]:
            self._observations[agent_id][metric_key] = []
        self._observations[agent_id][metric_key].append(value)
        # Ring buffer per metric
        if len(self._observations[agent_id][metric_key]) > self._max_records:
            self._observations[agent_id][metric_key] = self._observations[agent_id][metric_key][
                -self._max_records :
            ]
        count = len(self._observations[agent_id][metric_key])
        logger.debug(
            "agent_behavioral_baseline.observation_recorded",
            agent_id=agent_id,
            metric=metric_key,
            value=value,
            sample_count=count,
        )
        return {"agent_id": agent_id, "metric": metric_key, "sample_count": count}

    # -- compute --

    def compute_baseline(
        self,
        agent_id: str,
        metric: BaselineMetric,
    ) -> BaselineRecord:
        """Calculate statistical baseline (mean, stddev, min, max)."""
        metric_key = metric.value
        values = self._observations.get(agent_id, {}).get(metric_key, [])

        if len(values) < _MIN_SAMPLES_FOR_BASELINE:
            record = BaselineRecord(
                agent_id=agent_id,
                metric=metric,
                sample_count=len(values),
            )
            self._upsert_baseline(record)
            return record

        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        stddev = math.sqrt(variance)
        min_val = min(values)
        max_val = max(values)

        record = BaselineRecord(
            agent_id=agent_id,
            metric=metric,
            mean=round(mean, 4),
            stddev=round(stddev, 4),
            min_val=round(min_val, 4),
            max_val=round(max_val, 4),
            sample_count=n,
        )
        self._upsert_baseline(record)
        logger.info(
            "agent_behavioral_baseline.baseline_computed",
            agent_id=agent_id,
            metric=metric_key,
            mean=record.mean,
            stddev=record.stddev,
            samples=n,
        )
        return record

    # -- deviation check --

    def check_deviation(
        self,
        agent_id: str,
        metric: BaselineMetric,
        observed_value: float,
    ) -> dict[str, Any]:
        """Check if an observed value deviates from the baseline."""
        baseline = self._find_baseline(agent_id, metric)
        if not baseline or baseline.sample_count < _MIN_SAMPLES_FOR_BASELINE:
            return {
                "severity": DeviationSeverity.NORMAL.value,
                "z_score": 0.0,
                "expected_range": "insufficient_data",
            }

        if baseline.stddev == 0:
            z_score = 0.0 if observed_value == baseline.mean else 999.0
        else:
            z_score = abs(observed_value - baseline.mean) / baseline.stddev

        severity = self._z_to_severity(z_score)
        low = round(baseline.mean - 2 * baseline.stddev, 4)
        high = round(baseline.mean + 2 * baseline.stddev, 4)
        expected_range = f"[{low}, {high}]"

        # Record deviation if non-normal
        if severity != DeviationSeverity.NORMAL:
            event = DeviationEvent(
                agent_id=agent_id,
                metric=metric,
                observed_value=round(observed_value, 4),
                expected_range=expected_range,
                deviation_severity=severity,
                z_score=round(z_score, 4),
            )
            self._deviations.append(event)
            if len(self._deviations) > self._max_records:
                self._deviations = self._deviations[-self._max_records :]

        return {
            "severity": severity.value,
            "z_score": round(z_score, 4),
            "expected_range": expected_range,
        }

    # -- profile --

    def get_agent_profile(self, agent_id: str) -> dict[str, Any]:
        """Get all baselines for an agent."""
        agent_baselines = [b for b in self._baselines if b.agent_id == agent_id]
        if not agent_baselines:
            return {"agent_id": agent_id, "status": "no_baselines"}

        now = time.time()
        stale_cutoff = now - (_STALE_HOURS * 3600)
        profile: dict[str, Any] = {"agent_id": agent_id, "metrics": {}}
        stale_count = 0
        for b in agent_baselines:
            status = BaselineStatus.ESTABLISHED
            if b.sample_count < _MIN_SAMPLES_FOR_BASELINE:
                status = BaselineStatus.LEARNING
            elif b.last_updated < stale_cutoff:
                status = BaselineStatus.STALE
                stale_count += 1
            profile["metrics"][b.metric.value] = {
                "mean": b.mean,
                "stddev": b.stddev,
                "min": b.min_val,
                "max": b.max_val,
                "samples": b.sample_count,
                "status": status.value,
            }
        profile["stale_count"] = stale_count
        return profile

    # -- report / stats --

    def generate_report(self) -> BaselineReport:
        total_obs = sum(
            len(vals) for agent_data in self._observations.values() for vals in agent_data.values()
        )
        by_metric: dict[str, int] = {}
        for b in self._baselines:
            by_metric[b.metric.value] = by_metric.get(b.metric.value, 0) + 1

        by_severity: dict[str, int] = {}
        for d in self._deviations:
            by_severity[d.deviation_severity.value] = (
                by_severity.get(d.deviation_severity.value, 0) + 1
            )

        now = time.time()
        stale_cutoff = now - (_STALE_HOURS * 3600)
        stale = sum(1 for b in self._baselines if b.last_updated < stale_cutoff)

        recs: list[str] = []
        if stale > 0:
            recs.append(f"{stale} stale baselines — re-compute with fresh data")
        extreme = by_severity.get(DeviationSeverity.EXTREME.value, 0)
        if extreme > 0:
            recs.append(f"{extreme} extreme deviations detected — investigate agents")
        if not recs:
            recs.append("All baselines healthy, no extreme deviations")

        return BaselineReport(
            total_observations=total_obs,
            total_baselines=len(self._baselines),
            total_deviations=len(self._deviations),
            by_metric=by_metric,
            by_severity=by_severity,
            stale_baselines=stale,
            recommendations=recs,
        )

    def get_stats(self) -> dict[str, Any]:
        total_obs = sum(
            len(vals) for agent_data in self._observations.values() for vals in agent_data.values()
        )
        return {
            "total_observations": total_obs,
            "total_baselines": len(self._baselines),
            "total_deviations": len(self._deviations),
            "unique_agents": len(self._observations),
        }

    def clear_data(self) -> dict[str, str]:
        self._observations.clear()
        self._baselines.clear()
        self._deviations.clear()
        logger.info("agent_behavioral_baseline.cleared")
        return {"status": "cleared"}

    # -- internal helpers --

    def _upsert_baseline(self, record: BaselineRecord) -> None:
        """Insert or update a baseline record."""
        for i, existing in enumerate(self._baselines):
            if existing.agent_id == record.agent_id and existing.metric == record.metric:
                self._baselines[i] = record
                return
        self._baselines.append(record)

    def _find_baseline(self, agent_id: str, metric: BaselineMetric) -> BaselineRecord | None:
        for b in self._baselines:
            if b.agent_id == agent_id and b.metric == metric:
                return b
        return None

    @staticmethod
    def _z_to_severity(z_score: float) -> DeviationSeverity:
        if z_score < 1.0:
            return DeviationSeverity.NORMAL
        if z_score < 2.0:
            return DeviationSeverity.MINOR
        if z_score < 3.0:
            return DeviationSeverity.MODERATE
        if z_score < 4.0:
            return DeviationSeverity.SIGNIFICANT
        return DeviationSeverity.EXTREME
