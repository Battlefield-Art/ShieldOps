"""Security Scorecard Agent — Tool functions."""

from __future__ import annotations

from typing import Any

import structlog

from .models import (
    BenchmarkComparison,
    CompositeScore,
    DomainScore,
    ScoreGrade,
    SecurityDomain,
    SecurityInsight,
    TrendData,
)

logger = structlog.get_logger()

# Domain weights for composite scoring
_DOMAIN_WEIGHTS: dict[SecurityDomain, float] = {
    SecurityDomain.ENDPOINT: 1.2,
    SecurityDomain.NETWORK: 1.1,
    SecurityDomain.CLOUD: 1.3,
    SecurityDomain.IDENTITY: 1.4,
    SecurityDomain.DATA: 1.2,
    SecurityDomain.APPLICATION: 1.0,
    SecurityDomain.COMPLIANCE: 0.9,
    SecurityDomain.OPERATIONS: 0.8,
}

# Representative baseline scores
_BASELINE_SCORES: dict[SecurityDomain, dict[str, Any]] = {
    SecurityDomain.ENDPOINT: {
        "score": 72.0,
        "findings": 23,
        "critical": 2,
        "detail": "EDR coverage at 94%",
    },
    SecurityDomain.NETWORK: {
        "score": 68.0,
        "findings": 31,
        "critical": 3,
        "detail": "Segmentation gaps in dev VPC",
    },
    SecurityDomain.CLOUD: {
        "score": 61.0,
        "findings": 45,
        "critical": 5,
        "detail": "12 public S3 buckets found",
    },
    SecurityDomain.IDENTITY: {
        "score": 55.0,
        "findings": 52,
        "critical": 8,
        "detail": "MFA coverage at 78%",
    },
    SecurityDomain.DATA: {
        "score": 65.0,
        "findings": 28,
        "critical": 4,
        "detail": "DLP policy gaps in SaaS apps",
    },
    SecurityDomain.APPLICATION: {
        "score": 70.0,
        "findings": 19,
        "critical": 2,
        "detail": "SAST coverage at 85%",
    },
    SecurityDomain.COMPLIANCE: {
        "score": 78.0,
        "findings": 12,
        "critical": 1,
        "detail": "SOC 2 Type II in progress",
    },
    SecurityDomain.OPERATIONS: {
        "score": 75.0,
        "findings": 15,
        "critical": 1,
        "detail": "MTTD at 4.2 hours",
    },
}

# Industry benchmarks
_BENCHMARKS: list[dict[str, Any]] = [
    {
        "name": "SaaS Industry Average",
        "avg": 67.0,
    },
    {
        "name": "Financial Services",
        "avg": 74.0,
    },
    {
        "name": "Healthcare",
        "avg": 62.0,
    },
    {
        "name": "Top 10% Performers",
        "avg": 88.0,
    },
]


def _score_to_grade(score: float) -> ScoreGrade:
    """Convert numeric score to letter grade."""
    if score >= 95:
        return ScoreGrade.A_PLUS
    if score >= 85:
        return ScoreGrade.A
    if score >= 70:
        return ScoreGrade.B
    if score >= 55:
        return ScoreGrade.C
    if score >= 40:
        return ScoreGrade.D
    return ScoreGrade.F


class SecurityScorecardToolkit:
    """Toolkit for security posture scoring."""

    def __init__(
        self,
        agent_registry: Any | None = None,
        metrics_store: Any | None = None,
        benchmark_db: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._agent_registry = agent_registry
        self._metrics_store = metrics_store
        self._benchmark_db = benchmark_db
        self._repository = repository

    async def collect_domain_scores(
        self,
        tenant_id: str,
    ) -> list[DomainScore]:
        """Collect scores from all security domains."""
        logger.info(
            "scorecard.collect_domain_scores",
            tenant_id=tenant_id,
        )
        if self._agent_registry is not None:
            try:
                return await self._agent_registry.get_scores(
                    tenant_id,
                )
            except Exception:
                logger.warning(
                    "scorecard.registry_fallback",
                )

        scores: list[DomainScore] = []
        for domain, data in _BASELINE_SCORES.items():
            scores.append(
                DomainScore(
                    domain=domain,
                    score=data["score"],
                    grade=_score_to_grade(
                        data["score"],
                    ),
                    weight=_DOMAIN_WEIGHTS.get(
                        domain,
                        1.0,
                    ),
                    findings_count=data["findings"],
                    critical_issues=data["critical"],
                    details=data["detail"],
                )
            )
        return scores

    async def calculate_composite(
        self,
        domain_scores: list[DomainScore],
    ) -> CompositeScore:
        """Calculate weighted composite score."""
        logger.info(
            "scorecard.calculate_composite",
            domain_count=len(domain_scores),
        )
        if not domain_scores:
            return CompositeScore()

        total_weight = sum(s.weight for s in domain_scores)
        weighted_sum = sum(s.score * s.weight for s in domain_scores)
        composite = weighted_sum / total_weight if total_weight else 0.0

        sorted_scores = sorted(
            domain_scores,
            key=lambda s: s.score,
        )
        weakest = sorted_scores[0].domain.value
        strongest = sorted_scores[-1].domain.value

        return CompositeScore(
            total_score=round(composite, 1),
            grade=_score_to_grade(composite),
            domain_scores=domain_scores,
            weakest_domain=weakest,
            strongest_domain=strongest,
        )

    async def track_trends(
        self,
        composite_score: float,
    ) -> list[TrendData]:
        """Track 30/60/90 day score trends."""
        logger.info(
            "scorecard.track_trends",
            current_score=composite_score,
        )
        if self._metrics_store is not None:
            try:
                return await self._metrics_store.get_trends()
            except Exception:
                logger.warning(
                    "scorecard.trends_fallback",
                )

        return [
            TrendData(
                period="30d",
                score=composite_score - 2.3,
                delta=2.3,
                direction="improving",
                events_count=145,
            ),
            TrendData(
                period="60d",
                score=composite_score - 5.1,
                delta=5.1,
                direction="improving",
                events_count=312,
            ),
            TrendData(
                period="90d",
                score=composite_score - 3.8,
                delta=3.8,
                direction="improving",
                events_count=478,
            ),
        ]

    async def compare_benchmarks(
        self,
        composite_score: float,
    ) -> list[BenchmarkComparison]:
        """Compare score against industry benchmarks."""
        logger.info(
            "scorecard.compare_benchmarks",
            score=composite_score,
        )
        comparisons: list[BenchmarkComparison] = []
        for bench in _BENCHMARKS:
            gap = composite_score - bench["avg"]
            # Estimate percentile
            if gap > 15:
                pct = 90.0
            elif gap > 5:
                pct = 75.0
            elif gap > 0:
                pct = 60.0
            elif gap > -5:
                pct = 45.0
            else:
                pct = 30.0

            comparisons.append(
                BenchmarkComparison(
                    benchmark_name=bench["name"],
                    industry_avg=bench["avg"],
                    our_score=composite_score,
                    percentile=pct,
                    gap=round(gap, 1),
                )
            )
        return comparisons

    async def generate_insights(
        self,
        domain_scores: list[DomainScore],
        trends: list[TrendData],
    ) -> list[SecurityInsight]:
        """Generate security insights from scores."""
        logger.info(
            "scorecard.generate_insights",
            domain_count=len(domain_scores),
        )
        insights: list[SecurityInsight] = []

        # Find weakest domains
        sorted_scores = sorted(
            domain_scores,
            key=lambda s: s.score,
        )
        for ds in sorted_scores[:3]:
            insights.append(
                SecurityInsight(
                    category=ds.domain.value,
                    insight=(f"{ds.domain.value} score {ds.score} ({ds.grade.value})"),
                    severity=(
                        "critical" if ds.score < 50 else "high" if ds.score < 65 else "medium"
                    ),
                    recommendation=ds.details,
                    effort="medium",
                )
            )

        return insights
