"""Tool functions for the Governance Dashboard Agent."""

from __future__ import annotations

import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.governance_dashboard.models import (
    GovernanceMetric,
    PolicyAssessment,
    PolicyDomain,
    RiskPosture,
    RiskScore,
)

logger = structlog.get_logger()

# Default metric definitions per domain
DOMAIN_METRICS: dict[PolicyDomain, list[dict[str, Any]]] = {
    PolicyDomain.ACCESS_CONTROL: [
        {"name": "MFA adoption", "target": 100.0, "unit": "%"},
        {"name": "Privileged access reviews", "target": 95.0, "unit": "%"},
        {"name": "RBAC coverage", "target": 90.0, "unit": "%"},
    ],
    PolicyDomain.DATA_PROTECTION: [
        {"name": "Encryption at rest", "target": 100.0, "unit": "%"},
        {"name": "DLP policy coverage", "target": 90.0, "unit": "%"},
        {"name": "Data classification", "target": 85.0, "unit": "%"},
    ],
    PolicyDomain.INCIDENT_RESPONSE: [
        {"name": "MTTR (hours)", "target": 4.0, "unit": "hours"},
        {"name": "Runbook coverage", "target": 90.0, "unit": "%"},
        {"name": "Drill frequency", "target": 4.0, "unit": "per_quarter"},
    ],
    PolicyDomain.CHANGE_MANAGEMENT: [
        {"name": "Change approval rate", "target": 100.0, "unit": "%"},
        {"name": "Rollback readiness", "target": 95.0, "unit": "%"},
        {"name": "CAB review coverage", "target": 90.0, "unit": "%"},
    ],
    PolicyDomain.VENDOR_RISK: [
        {"name": "Vendor assessments complete", "target": 100.0, "unit": "%"},
        {"name": "Critical vendor SLA compliance", "target": 95.0, "unit": "%"},
        {"name": "Fourth-party risk mapped", "target": 80.0, "unit": "%"},
    ],
    PolicyDomain.BUSINESS_CONTINUITY: [
        {"name": "BCP test coverage", "target": 90.0, "unit": "%"},
        {"name": "RTO compliance", "target": 95.0, "unit": "%"},
        {"name": "DR site readiness", "target": 100.0, "unit": "%"},
    ],
}

# Simulated current values (in production, fetched from connectors)
SIMULATED_VALUES: dict[str, float] = {
    "MFA adoption": 94.0,
    "Privileged access reviews": 87.0,
    "RBAC coverage": 82.0,
    "Encryption at rest": 99.0,
    "DLP policy coverage": 76.0,
    "Data classification": 68.0,
    "MTTR (hours)": 6.2,
    "Runbook coverage": 78.0,
    "Drill frequency": 2.0,
    "Change approval rate": 97.0,
    "Rollback readiness": 88.0,
    "CAB review coverage": 91.0,
    "Vendor assessments complete": 82.0,
    "Critical vendor SLA compliance": 90.0,
    "Fourth-party risk mapped": 55.0,
    "BCP test coverage": 72.0,
    "RTO compliance": 85.0,
    "DR site readiness": 90.0,
}

# Posture thresholds
POSTURE_THRESHOLDS: list[tuple[float, RiskPosture]] = [
    (90.0, RiskPosture.STRONG),
    (75.0, RiskPosture.ADEQUATE),
    (60.0, RiskPosture.NEEDS_IMPROVEMENT),
    (40.0, RiskPosture.WEAK),
    (0.0, RiskPosture.CRITICAL),
]


class GovernanceDashboardToolkit:
    """Toolkit for governance dashboard operations."""

    def __init__(
        self,
        metrics_service: Any | None = None,
        policy_service: Any | None = None,
    ) -> None:
        self._metrics_service = metrics_service
        self._policy_service = policy_service

    async def collect_metrics(
        self,
        tenant_id: str,
    ) -> list[GovernanceMetric]:
        """Collect governance metrics across all domains."""
        now = time.time()
        metrics: list[GovernanceMetric] = []

        for domain, defs in DOMAIN_METRICS.items():
            for defn in defs:
                name = defn["name"]
                value = SIMULATED_VALUES.get(name, 0.0)

                if self._metrics_service is not None:
                    try:
                        value = await self._metrics_service.get(
                            name,
                            tenant_id,
                        )
                    except Exception:
                        logger.debug(
                            "metrics_lookup_failed",
                            metric=name,
                        )

                metrics.append(
                    GovernanceMetric(
                        id=f"gm-{uuid4().hex[:12]}",
                        name=name,
                        domain=domain,
                        value=value,
                        target=defn["target"],
                        unit=defn["unit"],
                        source="governance_collector",
                        collected_at=now,
                    )
                )

        logger.info(
            "governance.metrics_collected",
            tenant_id=tenant_id,
            count=len(metrics),
        )

        return metrics

    async def assess_policies(
        self,
        metrics: list[GovernanceMetric],
    ) -> list[PolicyAssessment]:
        """Assess policy adherence per domain."""
        now = time.time()
        assessments: list[PolicyAssessment] = []

        domain_metrics: dict[PolicyDomain, list[GovernanceMetric]] = {}
        for m in metrics:
            domain_metrics.setdefault(m.domain, []).append(m)

        for domain, dm_list in domain_metrics.items():
            passing = sum(
                1
                for m in dm_list
                if (m.value >= m.target if m.unit != "hours" else m.value <= m.target)
            )
            total = len(dm_list)
            adherence = (passing / total * 100.0) if total else 0.0

            gaps = [
                f"{m.name}: {m.value}{m.unit} vs target {m.target}{m.unit}"
                for m in dm_list
                if (m.value < m.target if m.unit != "hours" else m.value > m.target)
            ]

            assessments.append(
                PolicyAssessment(
                    id=f"pa-{uuid4().hex[:12]}",
                    domain=domain,
                    adherence_pct=round(adherence, 1),
                    controls_total=total,
                    controls_passing=passing,
                    gaps=gaps,
                    frameworks=["SOC 2", "ISO 27001", "NIST CSF"],
                    assessed_at=now,
                )
            )

        logger.info(
            "governance.policies_assessed",
            domains=len(assessments),
        )

        return assessments

    async def score_risk(
        self,
        assessments: list[PolicyAssessment],
        metrics: list[GovernanceMetric],
    ) -> list[RiskScore]:
        """Score risk posture per domain."""
        now = time.time()
        scores: list[RiskScore] = []

        for assessment in assessments:
            raw = assessment.adherence_pct
            posture = RiskPosture.CRITICAL
            for threshold, level in POSTURE_THRESHOLDS:
                if raw >= threshold:
                    posture = level
                    break

            factors = []
            if assessment.gaps:
                factors.append(f"{len(assessment.gaps)} control gaps")
            if raw < 75.0:
                factors.append("Below minimum adherence threshold")

            scores.append(
                RiskScore(
                    id=f"rs-{uuid4().hex[:12]}",
                    domain=assessment.domain,
                    score=round(raw, 1),
                    posture=posture,
                    factors=factors,
                    trend="stable",
                    scored_at=now,
                )
            )

        logger.info(
            "governance.risk_scored",
            domains=len(scores),
        )

        return scores

    async def compute_overall_posture(
        self,
        risk_scores: list[RiskScore],
    ) -> RiskPosture:
        """Compute the overall risk posture."""
        if not risk_scores:
            return RiskPosture.ADEQUATE

        avg_score = sum(s.score for s in risk_scores) / len(risk_scores)

        for threshold, level in POSTURE_THRESHOLDS:
            if avg_score >= threshold:
                return level

        return RiskPosture.CRITICAL

    async def build_executive_summary(
        self,
        metrics: list[GovernanceMetric],
        assessments: list[PolicyAssessment],
        risk_scores: list[RiskScore],
        overall_posture: RiskPosture,
        insights: list[str],
    ) -> str:
        """Build a text executive summary."""
        total_controls = sum(a.controls_total for a in assessments)
        passing_controls = sum(a.controls_passing for a in assessments)
        avg_adherence = (
            sum(a.adherence_pct for a in assessments) / len(assessments) if assessments else 0.0
        )

        summary = (
            f"Governance Posture: {overall_posture.value.upper()}. "
            f"Across {len(assessments)} domains, "
            f"{passing_controls}/{total_controls} controls passing "
            f"({avg_adherence:.1f}% avg adherence). "
            f"{len(insights)} insights generated."
        )

        logger.info(
            "governance.executive_summary_built",
            posture=overall_posture.value,
        )

        return summary
