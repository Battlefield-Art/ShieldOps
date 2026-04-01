"""Tool functions for the Unified Risk Dashboard.

Bridges risk signal collection, score normalization, risk
aggregation, posture calculation, and action prioritization
to the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.unified_risk_dashboard.models import (
    AggregatedRisk,
    NormalizedScore,
    PostureAssessment,
    PostureLevel,
    PrioritizedAction,
    RiskDomain,
    RiskSignal,
)

logger = structlog.get_logger()


class UnifiedRiskDashboardToolkit:
    """Tools for the unified risk dashboard agent."""

    def __init__(
        self,
        signal_collector: Any | None = None,
        score_normalizer: Any | None = None,
        risk_aggregator: Any | None = None,
        posture_calculator: Any | None = None,
        action_prioritizer: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._signal_collector = signal_collector
        self._score_normalizer = score_normalizer
        self._risk_aggregator = risk_aggregator
        self._posture_calculator = posture_calculator
        self._action_prioritizer = action_prioritizer
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Risk Signal Collection ----

    async def collect_risk_signals(
        self,
        tenant_id: str = "",
        domains: list[str] | None = None,
    ) -> list[RiskSignal]:
        """Collect risk signals from security agents."""
        signals: list[RiskSignal] = []
        now = datetime.now(UTC)

        if self._signal_collector is not None:
            try:
                raw = await self._signal_collector.collect(tenant_id=tenant_id, domains=domains)
                for item in raw:
                    signals.append(
                        RiskSignal(
                            signal_id=item.get("id", f"sig-{uuid4().hex[:8]}"),
                            source_agent=item.get("source_agent", ""),
                            domain=RiskDomain(item.get("domain", "network")),
                            severity=item.get("severity", "medium"),
                            raw_score=item.get("raw_score", 0.5),
                            title=item.get("title", ""),
                            description=item.get("description", ""),
                            affected_assets=item.get("affected_assets", []),
                            timestamp=item.get("timestamp", now),
                        )
                    )
            except Exception as e:
                logger.error(
                    "urd_signal_collection_failed",
                    error=str(e),
                )
        else:
            # Mock risk signal data
            risk_domains = list(RiskDomain)
            severities = [
                "critical",
                "high",
                "medium",
                "low",
            ]
            agents = [
                "threat_hunter",
                "vulnerability_manager",
                "identity_graph",
                "cloud_posture",
                "endpoint_behavior_monitor",
                "compliance_scanner",
                "supply_chain_scanner",
                "data_classification",
            ]
            count = random.randint(8, 20)  # noqa: S311
            for _unused_i in range(count):
                domain = random.choice(risk_domains)  # noqa: S311
                sev = random.choice(severities)  # noqa: S311
                agent = random.choice(agents)  # noqa: S311
                raw_score = round(  # noqa: S311
                    random.uniform(0.1, 0.95),  # noqa: S311
                    3,  # noqa: S311
                )
                signals.append(
                    RiskSignal(
                        signal_id=f"sig-{uuid4().hex[:8]}",
                        source_agent=agent,
                        domain=domain,
                        severity=sev,
                        raw_score=raw_score,
                        title=(f"{domain.value} risk from {agent}"),
                        description=(f"{sev.capitalize()} {domain.value} risk detected by {agent}"),
                        affected_assets=[
                            f"asset-{uuid4().hex[:6]}"
                            for _unused_j in range(  # noqa: S311
                                random.randint(1, 5)  # noqa: S311
                            )
                        ],
                        timestamp=now,
                        metadata={"mock": True},
                    )
                )

        logger.info(
            "urd_signals_collected",
            tenant_id=tenant_id,
            count=len(signals),
        )
        return signals

    # ---- Score Normalization ----

    async def normalize_scores(
        self,
        signals: list[RiskSignal],
    ) -> list[NormalizedScore]:
        """Normalize risk scores for cross-domain comparison."""
        normalized: list[NormalizedScore] = []

        domain_weights = {
            RiskDomain.IDENTITY: 1.2,
            RiskDomain.NETWORK: 1.0,
            RiskDomain.ENDPOINT: 1.1,
            RiskDomain.CLOUD: 1.15,
            RiskDomain.DATA: 1.3,
            RiskDomain.APPLICATION: 1.0,
            RiskDomain.COMPLIANCE: 0.9,
            RiskDomain.SUPPLY_CHAIN: 1.1,
        }

        for signal in signals:
            weight = domain_weights.get(signal.domain, 1.0)
            norm_score = min(round(signal.raw_score * weight, 3), 1.0)
            confidence = round(  # noqa: S311
                random.uniform(0.7, 0.99),  # noqa: S311
                3,  # noqa: S311
            )

            normalized.append(
                NormalizedScore(
                    score_id=f"nsc-{uuid4().hex[:8]}",
                    signal_id=signal.signal_id,
                    domain=signal.domain,
                    normalized_score=norm_score,
                    weight=weight,
                    confidence=confidence,
                    normalization_method="weighted_linear",
                )
            )

        logger.info(
            "urd_scores_normalized",
            signals=len(signals),
            normalized=len(normalized),
        )
        return normalized

    # ---- Risk Aggregation ----

    async def aggregate_risks(
        self,
        normalized: list[NormalizedScore],
    ) -> list[AggregatedRisk]:
        """Aggregate normalized scores by domain."""
        aggregated: list[AggregatedRisk] = []

        by_domain: dict[RiskDomain, list[NormalizedScore]] = {}
        for ns in normalized:
            by_domain.setdefault(ns.domain, []).append(ns)

        for domain, domain_scores in by_domain.items():
            avg_score = round(
                sum(s.normalized_score for s in domain_scores) / max(len(domain_scores), 1),
                3,
            )
            critical = sum(1 for s in domain_scores if s.normalized_score > 0.8)

            if avg_score > 0.7:
                trend = "worsening"
            elif avg_score < 0.3:
                trend = "improving"
            else:
                trend = "stable"

            top = sorted(
                domain_scores,
                key=lambda s: s.normalized_score,
                reverse=True,
            )[:3]

            aggregated.append(
                AggregatedRisk(
                    aggregation_id=f"agg-{uuid4().hex[:8]}",
                    domain=domain,
                    aggregate_score=avg_score,
                    signal_count=len(domain_scores),
                    critical_signals=critical,
                    trend=trend,
                    top_contributors=[s.signal_id for s in top],
                )
            )

        logger.info(
            "urd_risks_aggregated",
            domains=len(aggregated),
            signals=len(normalized),
        )
        return aggregated

    # ---- Posture Calculation ----

    async def calculate_posture(
        self,
        aggregated: list[AggregatedRisk],
    ) -> PostureAssessment:
        """Calculate overall security posture."""
        if not aggregated:
            return PostureAssessment(
                assessment_id=f"pa-{uuid4().hex[:8]}",
                posture_level=PostureLevel.ACCEPTABLE,
            )

        overall = round(
            sum(a.aggregate_score for a in aggregated) / max(len(aggregated), 1),
            3,
        )

        if overall > 0.8:
            level = PostureLevel.CRITICAL
        elif overall > 0.65:
            level = PostureLevel.AT_RISK
        elif overall > 0.5:
            level = PostureLevel.NEEDS_ATTENTION
        elif overall > 0.3:
            level = PostureLevel.ACCEPTABLE
        elif overall > 0.15:
            level = PostureLevel.STRONG
        else:
            level = PostureLevel.OPTIMAL

        domain_scores = {a.domain.value: a.aggregate_score for a in aggregated}

        sorted_domains = sorted(aggregated, key=lambda a: a.aggregate_score)
        strengths = [f"{a.domain.value}: {a.aggregate_score:.2f}" for a in sorted_domains[:2]]
        weaknesses = [f"{a.domain.value}: {a.aggregate_score:.2f}" for a in sorted_domains[-2:]]

        worsening = sum(1 for a in aggregated if a.trend == "worsening")
        improving = sum(1 for a in aggregated if a.trend == "improving")
        if worsening > improving:
            trend = "declining"
        elif improving > worsening:
            trend = "improving"
        else:
            trend = "stable"

        assessment = PostureAssessment(
            assessment_id=f"pa-{uuid4().hex[:8]}",
            overall_score=overall,
            posture_level=level,
            domain_scores=domain_scores,
            strengths=strengths,
            weaknesses=weaknesses,
            trend=trend,
        )

        logger.info(
            "urd_posture_calculated",
            overall=overall,
            level=level.value,
            trend=trend,
        )
        return assessment

    # ---- Action Prioritization ----

    async def prioritize_actions(
        self,
        aggregated: list[AggregatedRisk],
        posture: PostureAssessment,
    ) -> list[PrioritizedAction]:
        """Prioritize remediation actions."""
        actions: list[PrioritizedAction] = []

        action_templates = {
            RiskDomain.IDENTITY: "Review and rotate credentials",
            RiskDomain.NETWORK: "Update firewall rules",
            RiskDomain.ENDPOINT: "Patch endpoint vulnerabilities",
            RiskDomain.CLOUD: "Remediate cloud misconfigurations",
            RiskDomain.DATA: "Encrypt sensitive data at rest",
            RiskDomain.APPLICATION: "Fix application vulns",
            RiskDomain.COMPLIANCE: "Address compliance gaps",
            RiskDomain.SUPPLY_CHAIN: "Audit supply chain deps",
        }

        sorted_risks = sorted(
            aggregated,
            key=lambda a: a.aggregate_score,
            reverse=True,
        )

        for priority, risk in enumerate(sorted_risks, 1):
            template = action_templates.get(
                risk.domain,
                "Investigate and remediate",
            )
            reduction = round(min(risk.aggregate_score * 0.4, 0.5), 3)

            if risk.aggregate_score > 0.7:
                effort = "high"
            elif risk.aggregate_score > 0.4:
                effort = "medium"
            else:
                effort = "low"

            actions.append(
                PrioritizedAction(
                    action_id=f"act-{uuid4().hex[:8]}",
                    priority=priority,
                    domain=risk.domain,
                    title=template,
                    description=(
                        f"{template} to reduce "
                        f"{risk.domain.value} risk from "
                        f"{risk.aggregate_score:.2f}"
                    ),
                    risk_reduction=reduction,
                    effort=effort,
                    affected_assets=[],
                )
            )

        logger.info(
            "urd_actions_prioritized",
            risks=len(aggregated),
            actions=len(actions),
        )
        return actions

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a unified risk dashboard metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
