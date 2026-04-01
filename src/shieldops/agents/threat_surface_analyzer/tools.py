"""Tool functions for the Threat Surface Analyzer.

Bridges asset discovery, exposure mapping, risk assessment,
threat prioritization, and mitigation recommendation to
the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.threat_surface_analyzer.models import (
    AssetExposure,
    ExposureType,
    MitigationPlan,
    RiskAssessment,
    RiskCategory,
    SurfaceReport,
    ThreatVector,
)

logger = structlog.get_logger()


class ThreatSurfaceAnalyzerToolkit:
    """Tools for the threat surface analyzer agent.

    Injected into nodes at graph construction time to
    decouple agent logic from infrastructure implementations.
    """

    def __init__(
        self,
        asset_discovery_client: Any | None = None,
        vulnerability_scanner: Any | None = None,
        cloud_inventory: Any | None = None,
        threat_intel_client: Any | None = None,
        policy_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._asset_discovery = asset_discovery_client
        self._vuln_scanner = vulnerability_scanner
        self._cloud_inventory = cloud_inventory
        self._threat_intel = threat_intel_client
        self._policy_engine = policy_engine
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Asset Discovery ----

    async def discover_assets(
        self,
        tenant_id: str = "",
        environments: list[str] | None = None,
    ) -> list[AssetExposure]:
        """Discover assets across cloud, on-prem, and SaaS environments.

        Args:
            tenant_id: Tenant for scoping queries.
            environments: Environments to scan.

        Returns:
            List of AssetExposure objects.
        """
        if environments is None:
            environments = ["cloud", "on_prem", "saas"]

        assets: list[AssetExposure] = []
        now = datetime.now(UTC)

        if self._asset_discovery is not None:
            try:
                raw_assets = await self._asset_discovery.scan(
                    tenant_id=tenant_id, environments=environments
                )
                for raw in raw_assets:
                    assets.append(
                        AssetExposure(
                            asset_id=raw.get("id", f"asset-{uuid4().hex[:8]}"),
                            asset_name=raw.get("name", ""),
                            asset_type=raw.get("type", ""),
                            environment=raw.get("environment", ""),
                            exposure_type=ExposureType(raw.get("exposure_type", "public_endpoint")),
                            exposure_details=raw.get("details", ""),
                            discovered_at=now,
                            confidence=raw.get("confidence", 0.0),
                            tags=raw.get("tags", []),
                            metadata=raw.get("metadata", {}),
                        )
                    )
            except Exception as e:
                logger.error(
                    "tsa_asset_discovery_failed",
                    error=str(e),
                )
        else:
            # Mock asset data for unconfigured discovery
            asset_types = ["ec2", "s3_bucket", "rds", "api_gateway", "k8s_pod", "vm", "saas_app"]
            exposure_types = list(ExposureType)
            for env in environments:
                for _unused_i in range(random.randint(5, 15)):  # noqa: S311
                    assets.append(
                        AssetExposure(
                            asset_id=f"asset-{uuid4().hex[:8]}",
                            asset_name=f"{env}-{random.choice(asset_types)}-{uuid4().hex[:4]}",  # noqa: S311
                            asset_type=random.choice(asset_types),  # noqa: S311
                            environment=env,
                            exposure_type=random.choice(exposure_types),  # noqa: S311
                            exposure_details=f"Mock exposure in {env}",
                            discovered_at=now,
                            confidence=round(random.uniform(0.4, 0.95), 2),  # noqa: S311
                            tags=[env, "auto-discovered"],
                            metadata={"mock": True},
                        )
                    )

        logger.info(
            "tsa_assets_discovered",
            tenant_id=tenant_id,
            environments=environments,
            asset_count=len(assets),
        )
        return assets

    # ---- Exposure Mapping ----

    async def map_exposures(
        self,
        assets: list[AssetExposure],
    ) -> list[ThreatVector]:
        """Map exposures to threat vectors with attack paths.

        Args:
            assets: Discovered assets with exposures.

        Returns:
            List of ThreatVector objects.
        """
        vectors: list[ThreatVector] = []

        # Group assets by exposure type
        by_type: dict[ExposureType, list[AssetExposure]] = {}
        for asset in assets:
            by_type.setdefault(asset.exposure_type, []).append(asset)

        mitre_map = {
            ExposureType.PUBLIC_ENDPOINT: ["T1190", "T1133"],
            ExposureType.MISCONFIGURED_SERVICE: ["T1574", "T1562"],
            ExposureType.UNPATCHED_VULNERABILITY: ["T1203", "T1210"],
            ExposureType.EXPOSED_CREDENTIAL: ["T1078", "T1552"],
            ExposureType.SHADOW_IT: ["T1199", "T1195"],
            ExposureType.OVERPRIVILEGED_IDENTITY: ["T1078", "T1098"],
            ExposureType.INSECURE_API: ["T1190", "T1106"],
            ExposureType.OPEN_PORT: ["T1046", "T1133"],
        }

        for exp_type, group in by_type.items():
            exploitability = self._calc_exploitability(exp_type, len(group))
            impact = round(random.uniform(0.3, 0.95), 2)  # noqa: S311

            vectors.append(
                ThreatVector(
                    vector_id=f"vec-{uuid4().hex[:8]}",
                    source_asset_ids=[a.asset_id for a in group],
                    attack_path=(
                        f"{exp_type.value} -> lateral movement -> data access ({len(group)} assets)"
                    ),
                    exploitability=exploitability,
                    impact=impact,
                    mitre_techniques=mitre_map.get(exp_type, []),
                    description=(f"{len(group)} assets with {exp_type.value} exposure"),
                )
            )

        logger.info(
            "tsa_exposures_mapped",
            assets=len(assets),
            vectors=len(vectors),
        )
        return vectors

    # ---- Risk Assessment ----

    async def assess_risks(
        self,
        vectors: list[ThreatVector],
    ) -> list[RiskAssessment]:
        """Assess risk for each threat vector.

        Args:
            vectors: Mapped threat vectors.

        Returns:
            List of RiskAssessment objects.
        """
        assessments: list[RiskAssessment] = []

        for vector in vectors:
            risk_score = round((vector.exploitability * 0.4 + vector.impact * 0.6) * 10, 2)
            risk_score = min(risk_score, 10.0)
            likelihood = vector.exploitability
            category = self._score_to_category(risk_score)

            assessments.append(
                RiskAssessment(
                    assessment_id=f"risk-{uuid4().hex[:8]}",
                    vector_id=vector.vector_id,
                    risk_category=category,
                    risk_score=risk_score,
                    likelihood=likelihood,
                    impact_score=vector.impact,
                    affected_assets=vector.source_asset_ids[:10],
                    justification=(
                        f"Risk {risk_score:.1f}/10 — exploitability "
                        f"{vector.exploitability:.2f}, impact {vector.impact:.2f}"
                    ),
                )
            )

        logger.info(
            "tsa_risks_assessed",
            vectors=len(vectors),
            assessments=len(assessments),
            critical=sum(1 for a in assessments if a.risk_category == RiskCategory.CRITICAL),
        )
        return assessments

    # ---- Threat Prioritization ----

    async def prioritize_threats(
        self,
        assessments: list[RiskAssessment],
    ) -> list[dict[str, Any]]:
        """Prioritize assessed threats by risk score and business impact.

        Args:
            assessments: Risk assessment results.

        Returns:
            Prioritized list of threat dicts.
        """
        sorted_assessments = sorted(assessments, key=lambda a: a.risk_score, reverse=True)

        priorities: list[dict[str, Any]] = []
        for rank, assessment in enumerate(sorted_assessments, 1):
            priorities.append(
                {
                    "rank": rank,
                    "assessment_id": assessment.assessment_id,
                    "vector_id": assessment.vector_id,
                    "risk_category": assessment.risk_category.value,
                    "risk_score": assessment.risk_score,
                    "affected_asset_count": len(assessment.affected_assets),
                    "remediation_urgency": (
                        "immediate"
                        if assessment.risk_category == RiskCategory.CRITICAL
                        else "high"
                        if assessment.risk_category == RiskCategory.HIGH
                        else "medium"
                    ),
                }
            )

        logger.info(
            "tsa_threats_prioritized",
            total=len(priorities),
            critical=sum(1 for p in priorities if p["risk_category"] == "critical"),
        )
        return priorities

    # ---- Mitigation Recommendations ----

    async def recommend_mitigations(
        self,
        priorities: list[dict[str, Any]],
        assessments: list[RiskAssessment],
    ) -> list[MitigationPlan]:
        """Recommend specific mitigations for prioritized threats.

        Args:
            priorities: Prioritized threat list.
            assessments: Full risk assessments for context.

        Returns:
            List of MitigationPlan objects.
        """
        assessment_map = {a.assessment_id: a for a in assessments}
        mitigations: list[MitigationPlan] = []

        action_map = {
            RiskCategory.CRITICAL: [
                ("Isolate affected assets immediately", "1-2 hours", 0.8),
                ("Apply emergency patches", "2-4 hours", 0.7),
            ],
            RiskCategory.HIGH: [
                ("Restrict access to affected services", "4-8 hours", 0.6),
                ("Enable enhanced monitoring", "1-2 hours", 0.4),
            ],
            RiskCategory.MEDIUM: [
                ("Schedule patching cycle", "1-2 days", 0.5),
                ("Review access policies", "4-8 hours", 0.3),
            ],
            RiskCategory.LOW: [
                ("Add to next maintenance window", "1 week", 0.2),
            ],
        }

        for priority in priorities:
            assessment = assessment_map.get(priority.get("assessment_id", ""))
            if not assessment:
                continue

            actions = action_map.get(assessment.risk_category, [])
            for action_desc, effort, reduction in actions:
                mitigations.append(
                    MitigationPlan(
                        mitigation_id=f"mit-{uuid4().hex[:8]}",
                        assessment_id=assessment.assessment_id,
                        action=action_desc,
                        priority=priority.get("remediation_urgency", "medium"),
                        estimated_effort=effort,
                        expected_risk_reduction=reduction,
                        owner="security_team",
                        description=(
                            f"Mitigation for {assessment.risk_category.value} risk "
                            f"(score {assessment.risk_score:.1f})"
                        ),
                    )
                )

        logger.info(
            "tsa_mitigations_recommended",
            priorities=len(priorities),
            mitigations=len(mitigations),
        )
        return mitigations

    # ---- Report Generation ----

    async def generate_report(
        self,
        assets: list[AssetExposure],
        vectors: list[ThreatVector],
        assessments: list[RiskAssessment],
        mitigations: list[MitigationPlan],
    ) -> SurfaceReport:
        """Generate a summary report for the threat surface analysis.

        Args:
            assets: Discovered assets.
            vectors: Mapped threat vectors.
            assessments: Risk assessments.
            mitigations: Recommended mitigations.

        Returns:
            SurfaceReport object.
        """
        critical = sum(1 for a in assessments if a.risk_category == RiskCategory.CRITICAL)
        high = sum(1 for a in assessments if a.risk_category == RiskCategory.HIGH)
        avg_score = sum(a.risk_score for a in assessments) / max(len(assessments), 1)

        report = SurfaceReport(
            report_id=f"rpt-{uuid4().hex[:8]}",
            title=f"Threat Surface Analysis: {len(assets)} assets",
            executive_summary=(
                f"Discovered {len(assets)} assets with "
                f"{len(vectors)} threat vectors. "
                f"{critical} critical and {high} high risks identified. "
                f"Average risk score: {avg_score:.1f}/10. "
                f"{len(mitigations)} mitigations recommended."
            ),
            assets_discovered=len(assets),
            exposures_mapped=len(vectors),
            risks_assessed=len(assessments),
            critical_count=critical,
            high_count=high,
            mitigations_recommended=len(mitigations),
            overall_risk_score=round(avg_score, 2),
            generated_at=datetime.now(UTC),
        )

        logger.info(
            "tsa_report_generated",
            assets=len(assets),
            critical=critical,
            high=high,
        )
        return report

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a threat surface analyzer metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )

    # ---- Private helpers ----

    @staticmethod
    def _calc_exploitability(
        exposure_type: ExposureType,
        asset_count: int,
    ) -> float:
        """Calculate exploitability score 0-1."""
        base_scores = {
            ExposureType.EXPOSED_CREDENTIAL: 0.9,
            ExposureType.UNPATCHED_VULNERABILITY: 0.8,
            ExposureType.PUBLIC_ENDPOINT: 0.7,
            ExposureType.INSECURE_API: 0.7,
            ExposureType.OPEN_PORT: 0.6,
            ExposureType.MISCONFIGURED_SERVICE: 0.6,
            ExposureType.OVERPRIVILEGED_IDENTITY: 0.5,
            ExposureType.SHADOW_IT: 0.4,
        }
        base = base_scores.get(exposure_type, 0.5)
        # More assets = slightly higher exploitability
        scale = min(asset_count * 0.02, 0.1)
        return min(round(base + scale, 2), 1.0)

    @staticmethod
    def _score_to_category(score: float) -> RiskCategory:
        """Map 0-10 risk score to RiskCategory enum."""
        if score >= 8.0:
            return RiskCategory.CRITICAL
        if score >= 6.0:
            return RiskCategory.HIGH
        if score >= 4.0:
            return RiskCategory.MEDIUM
        if score >= 2.0:
            return RiskCategory.LOW
        return RiskCategory.INFORMATIONAL
