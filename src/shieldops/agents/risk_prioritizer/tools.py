"""Tool functions for the Risk Prioritizer Agent."""

from __future__ import annotations

import contextlib
from typing import Any

import structlog

from shieldops.agents.risk_prioritizer.models import (
    ActionPlan,
    ActionUrgency,
    ContextEnrichment,
    FindingInput,
    RankedFinding,
    RiskScore,
)

logger = structlog.get_logger()

_SEVERITY_BASE: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}


class RiskPrioritizerToolkit:
    """Toolkit for risk-based finding prioritization."""

    def __init__(
        self,
        finding_store: Any | None = None,
        asset_inventory: Any | None = None,
        epss_client: Any | None = None,
        cmdb_client: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._finding_store = finding_store
        self._asset_inventory = asset_inventory
        self._epss_client = epss_client
        self._cmdb_client = cmdb_client
        self._repository = repository

    async def collect_findings(
        self,
        tenant_id: str,
    ) -> list[FindingInput]:
        """Collect findings to prioritize."""
        logger.info(
            "risk_prioritizer.collect",
            tenant_id=tenant_id,
        )
        if self._finding_store is not None:
            try:
                return await self._finding_store.list(tenant_id)
            except Exception:
                logger.warning("risk_prioritizer.collect_fallback")
        return []

    async def enrich_context(
        self,
        findings: list[FindingInput],
    ) -> list[ContextEnrichment]:
        """Enrich findings with business context."""
        logger.info(
            "risk_prioritizer.enrich",
            count=len(findings),
        )
        enrichments: list[ContextEnrichment] = []
        for f in findings:
            enrichment = ContextEnrichment(
                finding_id=f.id,
                asset_criticality="medium",
                data_sensitivity="internal",
                exposure_type="internal",
                environment="production",
            )
            if self._cmdb_client is not None:
                try:
                    ctx = await self._cmdb_client.get(f.asset)
                    enrichment = ContextEnrichment(
                        finding_id=f.id,
                        asset_criticality=ctx.get("criticality", "medium"),
                        data_sensitivity=ctx.get("sensitivity", "internal"),
                        exposure_type=ctx.get("exposure", "internal"),
                        regulatory_scope=ctx.get("regulations", []),
                        business_owner=ctx.get("owner", ""),
                        environment=ctx.get("env", "production"),
                    )
                except Exception:
                    logger.warning(
                        "risk_prioritizer.enrich_err",
                        finding_id=f.id,
                    )
            enrichments.append(enrichment)
        return enrichments

    async def score_risk(
        self,
        findings: list[FindingInput],
        enrichments: list[ContextEnrichment],
    ) -> list[RiskScore]:
        """Calculate composite risk scores."""
        logger.info(
            "risk_prioritizer.score",
            count=len(findings),
        )
        enrich_map = {e.finding_id: e for e in enrichments}
        scores: list[RiskScore] = []
        criticality_weights: dict[str, float] = {
            "critical": 10.0,
            "high": 8.0,
            "medium": 5.0,
            "low": 3.0,
        }
        for f in findings:
            ctx = enrich_map.get(f.id)
            base = f.cvss_score or _SEVERITY_BASE.get(f.severity.lower(), 5.0)
            exploit = min(base * 1.1, 10.0)
            blast = 5.0
            crit = criticality_weights.get(
                ctx.asset_criticality if ctx else "medium",
                5.0,
            )
            data_sens = 5.0
            reg = min(len(ctx.regulatory_scope) * 2.0, 10.0) if ctx else 0.0
            epss = 0.0
            if self._epss_client and f.cve_id:
                with contextlib.suppress(Exception):
                    epss = await self._epss_client.score(f.cve_id)
            composite = (
                exploit * 0.3
                + blast * 0.2
                + crit * 0.2
                + data_sens * 0.15
                + reg * 0.1
                + epss * 10 * 0.05
            )
            scores.append(
                RiskScore(
                    finding_id=f.id,
                    composite_score=round(composite, 2),
                    exploitability=round(exploit, 2),
                    blast_radius=round(blast, 2),
                    asset_criticality=round(crit, 2),
                    data_sensitivity=round(data_sens, 2),
                    regulatory_impact=round(reg, 2),
                    epss_score=round(epss, 4),
                )
            )
        return scores

    async def rank_findings(
        self,
        findings: list[FindingInput],
        scores: list[RiskScore],
    ) -> list[RankedFinding]:
        """Rank findings by composite risk score."""
        logger.info(
            "risk_prioritizer.rank",
            count=len(findings),
        )
        finding_map = {f.id: f for f in findings}
        sorted_scores = sorted(
            scores,
            key=lambda s: s.composite_score,
            reverse=True,
        )
        ranked: list[RankedFinding] = []
        for rank, s in enumerate(sorted_scores, 1):
            f = finding_map.get(s.finding_id)
            title = f.title if f else s.finding_id
            urgency = ActionUrgency.SCHEDULED
            if s.composite_score >= 8.0:
                urgency = ActionUrgency.IMMEDIATE
            elif s.composite_score >= 6.0:
                urgency = ActionUrgency.URGENT
            elif s.composite_score < 3.0:
                urgency = ActionUrgency.DEFERRED
            factors: list[str] = []
            if s.exploitability >= 8.0:
                factors.append("high_exploitability")
            if s.asset_criticality >= 8.0:
                factors.append("critical_asset")
            if s.regulatory_impact >= 5.0:
                factors.append("regulatory")
            ranked.append(
                RankedFinding(
                    finding_id=s.finding_id,
                    title=title,
                    rank=rank,
                    composite_score=s.composite_score,
                    urgency=urgency,
                    top_risk_factors=factors,
                )
            )
        return ranked

    async def generate_action_plans(
        self,
        ranked: list[RankedFinding],
    ) -> list[ActionPlan]:
        """Generate action plans for ranked findings."""
        logger.info(
            "risk_prioritizer.action_plans",
            count=len(ranked),
        )
        plans: list[ActionPlan] = []
        for rf in ranked:
            effort = {
                ActionUrgency.IMMEDIATE: 2.0,
                ActionUrgency.URGENT: 4.0,
                ActionUrgency.SCHEDULED: 8.0,
                ActionUrgency.DEFERRED: 16.0,
                ActionUrgency.ACCEPTED: 0.0,
            }.get(rf.urgency, 8.0)
            plans.append(
                ActionPlan(
                    finding_id=rf.finding_id,
                    urgency=rf.urgency,
                    recommended_action=(
                        "Patch or mitigate immediately"
                        if rf.urgency == ActionUrgency.IMMEDIATE
                        else "Schedule remediation"
                    ),
                    estimated_effort_hours=effort,
                    assigned_team="security",
                )
            )
        return plans
