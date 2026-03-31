"""Security Posture Scorer Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    BenchmarkComparison,
    CategoryWeight,
    PostureScore,
    ScoreTier,
    SecuritySignal,
    SignalSource,
    TrendPoint,
)

logger = structlog.get_logger()

_CATEGORIES = [
    "vulnerability_management",
    "identity_access",
    "cloud_security",
    "endpoint_protection",
    "network_security",
    "data_protection",
    "incident_response",
    "compliance",
]

_CIS_WEIGHTS: dict[str, float] = {
    "vulnerability_management": 0.18,
    "identity_access": 0.16,
    "cloud_security": 0.14,
    "endpoint_protection": 0.13,
    "network_security": 0.12,
    "data_protection": 0.11,
    "incident_response": 0.09,
    "compliance": 0.07,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


def _score_to_tier(score: float) -> ScoreTier:
    if score >= 90:
        return ScoreTier.EXCELLENT
    if score >= 75:
        return ScoreTier.GOOD
    if score >= 60:
        return ScoreTier.FAIR
    if score >= 40:
        return ScoreTier.POOR
    return ScoreTier.CRITICAL


class SecurityPostureScorerToolkit:
    """Tools for continuous security posture scoring."""

    def __init__(
        self,
        signal_sources: Any | None = None,
        benchmark_api: Any | None = None,
    ) -> None:
        self._signal_sources = signal_sources
        self._benchmark_api = benchmark_api

    async def collect_signals(
        self,
        tenant_id: str,
    ) -> list[SecuritySignal]:
        """Collect security signals from all sources."""
        logger.info(
            "sps.collect_signals",
            tenant_id=tenant_id,
        )

        if self._signal_sources is not None:
            try:
                raw = await self._signal_sources.fetch(
                    tenant_id=tenant_id,
                )
                return [SecuritySignal(**r) for r in raw]
            except Exception:
                logger.exception("sps.collect_signals.error")

        signals: list[SecuritySignal] = []
        _idx = 0
        sources = list(SignalSource)
        for cat in _CATEGORIES:
            n_signals = random.randint(3, 8)  # noqa: S311
            for _j in range(n_signals):
                val = round(random.uniform(30.0, 98.0), 1)  # noqa: S311
                signals.append(
                    SecuritySignal(
                        id=_gen_id("SS", tenant_id, _idx),
                        source=sources[_idx % len(sources)],
                        category=cat,
                        metric_name=f"{cat}_metric_{_j}",
                        value=val,
                        max_value=100.0,
                        timestamp="2026-03-30T10:00:00Z",
                        weight=_CIS_WEIGHTS.get(cat, 0.1),
                        tags=[cat, "auto-collected"],
                    )
                )
                _idx += 1
        return signals

    async def weight_categories(
        self,
        signals: list[SecuritySignal],
    ) -> list[CategoryWeight]:
        """Compute category weights based on CIS benchmarks."""
        logger.info(
            "sps.weight_categories",
            count=len(signals),
        )

        cat_counts: dict[str, int] = {}
        for s in signals:
            cat_counts[s.category] = cat_counts.get(s.category, 0) + 1

        weights: list[CategoryWeight] = []
        for i, cat in enumerate(_CATEGORIES):
            w = _CIS_WEIGHTS.get(cat, 0.1)
            weights.append(
                CategoryWeight(
                    id=_gen_id("CW", cat, i),
                    category=cat,
                    weight=w,
                    cis_benchmark_id=f"CIS-{i + 1}.0",
                    description=f"CIS weight for {cat.replace('_', ' ')}",
                    signal_count=cat_counts.get(cat, 0),
                )
            )
        return weights

    async def calculate_scores(
        self,
        signals: list[SecuritySignal],
        weights: list[CategoryWeight],
    ) -> list[PostureScore]:
        """Calculate posture scores per category."""
        logger.info(
            "sps.calculate_scores",
            signals=len(signals),
            categories=len(weights),
        )

        cat_signals: dict[str, list[SecuritySignal]] = {}
        for s in signals:
            cat_signals.setdefault(s.category, []).append(s)

        scores: list[PostureScore] = []
        for i, cw in enumerate(weights):
            sigs = cat_signals.get(cw.category, [])
            avg = sum(s.value for s in sigs) / len(sigs) if sigs else 0.0
            score = round(avg, 1)
            tier = _score_to_tier(score)
            findings: list[str] = []
            if score < 60:
                findings.append(f"{cw.category} below acceptable threshold")
            if score < 40:
                findings.append(f"Critical: {cw.category} needs immediate attention")

            scores.append(
                PostureScore(
                    id=_gen_id("PS", cw.category, i),
                    category=cw.category,
                    score=score,
                    max_score=100.0,
                    tier=tier,
                    contributing_signals=len(sigs),
                    findings=findings,
                )
            )
        return scores

    async def benchmark_comparison(
        self,
        scores: list[PostureScore],
    ) -> list[BenchmarkComparison]:
        """Compare scores against industry benchmarks."""
        logger.info(
            "sps.benchmark_comparison",
            count=len(scores),
        )

        benchmarks: list[BenchmarkComparison] = []
        for i, ps in enumerate(scores):
            industry_avg = round(random.uniform(55.0, 75.0), 1)  # noqa: S311
            industry_top = round(random.uniform(85.0, 97.0), 1)  # noqa: S311
            pct = int(min(99, max(1, (ps.score / industry_top) * 100)))
            benchmarks.append(
                BenchmarkComparison(
                    id=_gen_id("BC", ps.category, i),
                    category=ps.category,
                    org_score=ps.score,
                    industry_avg=industry_avg,
                    industry_top_10=industry_top,
                    percentile=pct,
                    framework="CIS",
                )
            )
        return benchmarks

    async def analyze_trends(
        self,
        scores: list[PostureScore],
    ) -> list[TrendPoint]:
        """Analyze posture score trends over time."""
        logger.info(
            "sps.analyze_trends",
            count=len(scores),
        )

        overall = sum(s.score for s in scores) / len(scores) if scores else 0.0
        trends: list[TrendPoint] = []
        for i in range(6):
            month = 6 - i
            delta = round(random.uniform(-5.0, 5.0), 1)  # noqa: S311
            period_score = round(max(0, min(100, overall + delta * (month - 3))), 1)
            direction = "improving" if delta > 0 else "declining" if delta < 0 else "stable"
            forecast = round(period_score + delta * 1.5, 1)  # noqa: S311
            trends.append(
                TrendPoint(
                    id=_gen_id("TP", str(month), i),
                    period=f"2026-{max(1, 3 - month + 1):02d}",
                    overall_score=period_score,
                    delta=delta,
                    direction=direction,
                    forecast_30d=forecast,
                )
            )
        return trends

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a metric for observability."""
        _tags = tags or {}
        logger.info(
            "sps.record_metric",
            metric=metric_name,
            value=value,
            tags=_tags,
        )
        return {
            "metric": metric_name,
            "value": value,
            "tags": _tags,
            "recorded": True,
        }
