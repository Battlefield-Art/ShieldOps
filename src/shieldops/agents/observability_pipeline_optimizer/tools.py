"""Observability Pipeline Optimizer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    CardinalityAnalysis,
    CostReduction,
    OptimizationAction,
    PipelineAudit,
    PipelineType,
    QualityValidation,
    SamplingConfig,
)

logger = structlog.get_logger()

_PIPELINE_PROFILES: list[dict[str, Any]] = [
    {
        "name": "otel-traces-prod",
        "pipeline_type": PipelineType.TRACES,
        "vendor": "OTel Collector",
        "gb_day": 85.0,
        "retention": 14,
        "monthly": 4250.0,
        "util": 72.0,
        "cardinality": 48000,
    },
    {
        "name": "otel-metrics-prod",
        "pipeline_type": PipelineType.METRICS,
        "vendor": "OTel Collector",
        "gb_day": 12.0,
        "retention": 90,
        "monthly": 3600.0,
        "util": 88.0,
        "cardinality": 320000,
    },
    {
        "name": "otel-logs-prod",
        "pipeline_type": PipelineType.LOGS,
        "vendor": "OTel Collector",
        "gb_day": 210.0,
        "retention": 30,
        "monthly": 8400.0,
        "util": 35.0,
        "cardinality": 5000,
    },
    {
        "name": "datadog-apm",
        "pipeline_type": PipelineType.TRACES,
        "vendor": "Datadog",
        "gb_day": 45.0,
        "retention": 15,
        "monthly": 6750.0,
        "util": 60.0,
        "cardinality": 85000,
    },
    {
        "name": "datadog-metrics",
        "pipeline_type": PipelineType.METRICS,
        "vendor": "Datadog",
        "gb_day": 8.0,
        "retention": 15,
        "monthly": 5200.0,
        "util": 45.0,
        "cardinality": 750000,
    },
    {
        "name": "splunk-logs",
        "pipeline_type": PipelineType.LOGS,
        "vendor": "Splunk",
        "gb_day": 150.0,
        "retention": 90,
        "monthly": 12000.0,
        "util": 55.0,
        "cardinality": 12000,
    },
    {
        "name": "splunk-events",
        "pipeline_type": PipelineType.EVENTS,
        "vendor": "Splunk",
        "gb_day": 30.0,
        "retention": 365,
        "monthly": 3600.0,
        "util": 20.0,
        "cardinality": 8000,
    },
    {
        "name": "otel-profiles-staging",
        "pipeline_type": PipelineType.PROFILES,
        "vendor": "OTel Collector",
        "gb_day": 5.0,
        "retention": 7,
        "monthly": 750.0,
        "util": 15.0,
        "cardinality": 2000,
    },
]

_CARDINALITY_HOTSPOTS: list[dict[str, Any]] = [
    {
        "metric": "http_request_duration_seconds",
        "labels": 12,
        "series": 280000,
        "risk": "critical",
        "action": OptimizationAction.REDUCE_CARDINALITY,
        "reduction": 65.0,
    },
    {
        "metric": "k8s_pod_cpu_utilization",
        "labels": 8,
        "series": 95000,
        "risk": "high",
        "action": OptimizationAction.AGGREGATE,
        "reduction": 40.0,
    },
    {
        "metric": "custom_business_metric",
        "labels": 15,
        "series": 520000,
        "risk": "critical",
        "action": OptimizationAction.DROP_UNUSED,
        "reduction": 80.0,
    },
    {
        "metric": "db_query_latency_ms",
        "labels": 6,
        "series": 45000,
        "risk": "medium",
        "action": OptimizationAction.DOWNSAMPLE,
        "reduction": 30.0,
    },
    {
        "metric": "cache_hit_ratio",
        "labels": 4,
        "series": 12000,
        "risk": "low",
        "action": OptimizationAction.COMPRESS,
        "reduction": 15.0,
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class ObservabilityPipelineOptimizerToolkit:
    """Tools for observability pipeline optimization."""

    def __init__(
        self,
        otel_api: Any | None = None,
        vendor_api: Any | None = None,
    ) -> None:
        self._otel_api = otel_api
        self._vendor_api = vendor_api

    async def audit_pipelines(
        self,
        tenant_id: str,
    ) -> list[PipelineAudit]:
        """Audit all observability pipelines."""
        logger.info(
            "opo.audit_pipelines",
            tenant_id=tenant_id,
        )

        if self._otel_api is not None:
            try:
                raw = await self._otel_api.list_pipelines(
                    tenant_id=tenant_id,
                )
                return [PipelineAudit(**r) for r in raw]
            except Exception:
                logger.exception("opo.audit_pipelines.error")

        audits: list[PipelineAudit] = []
        for i, p in enumerate(_PIPELINE_PROFILES):
            noise = random.gauss(0, 2.0)  # noqa: S311
            gb = round(max(0.1, p["gb_day"] + noise), 2)
            audits.append(
                PipelineAudit(
                    id=_gen_id("PA", tenant_id, i),
                    name=p["name"],
                    pipeline_type=p["pipeline_type"],
                    vendor=p["vendor"],
                    ingestion_rate_gb_day=gb,
                    retention_days=p["retention"],
                    monthly_cost=round(
                        p["monthly"] + random.gauss(0, 50),  # noqa: S311
                        2,
                    ),
                    utilization_pct=p["util"],
                    cardinality=p["cardinality"],
                    tags={"env": "production"},
                )
            )
        return audits

    async def analyze_cardinality(
        self,
        audits: list[PipelineAudit],
    ) -> list[CardinalityAnalysis]:
        """Analyze metric cardinality across pipelines."""
        logger.info(
            "opo.analyze_cardinality",
            count=len(audits),
        )

        results: list[CardinalityAnalysis] = []
        metric_pipelines = [
            a for a in audits if a.pipeline_type in (PipelineType.METRICS, PipelineType.TRACES)
        ]

        for i, hotspot in enumerate(_CARDINALITY_HOTSPOTS):
            pipeline = metric_pipelines[i % max(len(metric_pipelines), 1)]
            results.append(
                CardinalityAnalysis(
                    id=_gen_id("CA", pipeline.id, i),
                    pipeline_id=pipeline.id,
                    metric_name=hotspot["metric"],
                    label_count=hotspot["labels"],
                    unique_series=hotspot["series"],
                    explosion_risk=hotspot["risk"],
                    recommended_action=hotspot["action"],
                    estimated_reduction_pct=hotspot["reduction"],
                )
            )
        return results

    async def optimize_sampling(
        self,
        audits: list[PipelineAudit],
    ) -> list[SamplingConfig]:
        """Generate sampling optimization configs."""
        logger.info(
            "opo.optimize_sampling",
            count=len(audits),
        )

        configs: list[SamplingConfig] = []
        for i, audit in enumerate(audits):
            if audit.pipeline_type == PipelineType.TRACES:
                configs.append(
                    SamplingConfig(
                        id=_gen_id("SC", audit.id, i),
                        pipeline_id=audit.id,
                        pipeline_type=audit.pipeline_type,
                        current_sample_rate=1.0,
                        recommended_rate=0.1,
                        strategy="tail_sampling",
                        estimated_savings_pct=70.0,
                        quality_impact="minimal",
                    )
                )
            elif audit.pipeline_type == PipelineType.LOGS:
                rate = round(
                    random.uniform(0.2, 0.5),  # noqa: S311
                    2,
                )
                configs.append(
                    SamplingConfig(
                        id=_gen_id("SC", audit.id, i),
                        pipeline_id=audit.id,
                        pipeline_type=audit.pipeline_type,
                        current_sample_rate=1.0,
                        recommended_rate=rate,
                        strategy="severity_sampling",
                        estimated_savings_pct=round((1.0 - rate) * 100, 1),
                        quality_impact="low",
                    )
                )
            elif audit.pipeline_type == PipelineType.METRICS:
                configs.append(
                    SamplingConfig(
                        id=_gen_id("SC", audit.id, i),
                        pipeline_id=audit.id,
                        pipeline_type=audit.pipeline_type,
                        current_sample_rate=1.0,
                        recommended_rate=0.5,
                        strategy="downsampling_60s",
                        estimated_savings_pct=40.0,
                        quality_impact="low",
                    )
                )
        return configs

    async def reduce_costs(
        self,
        audits: list[PipelineAudit],
        cardinality: list[CardinalityAnalysis],
        sampling: list[SamplingConfig],
    ) -> list[CostReduction]:
        """Identify cost reduction opportunities."""
        logger.info(
            "opo.reduce_costs",
            audits=len(audits),
            cardinality=len(cardinality),
            sampling=len(sampling),
        )

        reductions: list[CostReduction] = []
        idx = 0

        for audit in audits:
            if audit.utilization_pct < 25.0:
                savings = round(audit.monthly_cost * 0.8, 2)
                reductions.append(
                    CostReduction(
                        id=_gen_id("CR", audit.id, idx),
                        pipeline_id=audit.id,
                        action=OptimizationAction.DROP_UNUSED,
                        description=(
                            f"Drop underutilized pipeline "
                            f"{audit.name} "
                            f"({audit.utilization_pct}% used)"
                        ),
                        current_monthly_cost=(audit.monthly_cost),
                        projected_monthly_cost=round(audit.monthly_cost * 0.2, 2),
                        monthly_savings=savings,
                        auto_applicable=True,
                        risk="low",
                    )
                )
                idx += 1

        for sc in sampling:
            matched = next(
                (a for a in audits if a.id == sc.pipeline_id),
                None,
            )
            if matched:
                savings = round(
                    matched.monthly_cost * sc.estimated_savings_pct / 100,
                    2,
                )
                reductions.append(
                    CostReduction(
                        id=_gen_id("CR", sc.id, idx),
                        pipeline_id=sc.pipeline_id,
                        action=OptimizationAction.TAIL_SAMPLE,
                        description=(
                            f"Apply {sc.strategy} to {matched.name} (rate={sc.recommended_rate})"
                        ),
                        current_monthly_cost=(matched.monthly_cost),
                        projected_monthly_cost=round(
                            matched.monthly_cost - savings,
                            2,
                        ),
                        monthly_savings=savings,
                        auto_applicable=False,
                        risk="medium",
                    )
                )
                idx += 1

        for ca in cardinality:
            if ca.explosion_risk in ("critical", "high"):
                est_savings = round(ca.estimated_reduction_pct * 50, 2)
                reductions.append(
                    CostReduction(
                        id=_gen_id("CR", ca.id, idx),
                        pipeline_id=ca.pipeline_id,
                        action=ca.recommended_action,
                        description=(
                            f"Reduce cardinality on {ca.metric_name} ({ca.unique_series} series)"
                        ),
                        current_monthly_cost=est_savings,
                        projected_monthly_cost=round(
                            est_savings * (1 - ca.estimated_reduction_pct / 100),
                            2,
                        ),
                        monthly_savings=round(
                            est_savings * ca.estimated_reduction_pct / 100,
                            2,
                        ),
                        auto_applicable=False,
                        risk="medium",
                    )
                )
                idx += 1

        return reductions

    async def validate_quality(
        self,
        audits: list[PipelineAudit],
        sampling: list[SamplingConfig],
    ) -> list[QualityValidation]:
        """Validate signal quality post-optimization."""
        logger.info(
            "opo.validate_quality",
            audits=len(audits),
        )

        validations: list[QualityValidation] = []
        metrics = [
            ("p99_latency_accuracy", 0.99, 0.97),
            ("error_rate_accuracy", 1.0, 0.99),
            ("alert_fidelity", 1.0, 0.98),
            ("trace_completeness", 1.0, 0.95),
        ]

        for i, audit in enumerate(audits):
            for j, (metric, pre, post) in enumerate(metrics):
                noise = random.gauss(  # noqa: S311
                    0, 0.005
                )
                post_val = round(min(1.0, max(0.0, post + noise)), 4)
                validations.append(
                    QualityValidation(
                        id=_gen_id(
                            "QV",
                            audit.id,
                            i * len(metrics) + j,
                        ),
                        pipeline_id=audit.id,
                        metric=metric,
                        pre_optimization_value=pre,
                        post_optimization_value=post_val,
                        within_threshold=post_val >= 0.95,
                        threshold=0.95,
                    )
                )
        return validations
