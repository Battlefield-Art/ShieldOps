"""Tool functions for the Supply Chain Risk Engine.

Bridges dependency inventory, vulnerability scanning, risk
assessment, blast radius mapping, and mitigation recommendation
to the LangGraph nodes.
"""

from __future__ import annotations

import random  # noqa: S311
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.supply_chain_risk_engine.models import (
    BlastRadiusMapping,
    DependencyRecord,
    DependencyType,
    MitigationRecommendation,
    RiskAssessment,
    SupplyChainRisk,
    VulnerabilityScan,
)

logger = structlog.get_logger()


class SupplyChainRiskEngineToolkit:
    """Tools for the supply chain risk engine agent."""

    def __init__(
        self,
        package_registry: Any | None = None,
        vuln_scanner: Any | None = None,
        sbom_store: Any | None = None,
        dependency_graph: Any | None = None,
        remediation_engine: Any | None = None,
        repository: Any | None = None,
    ) -> None:
        self._package_registry = package_registry
        self._vuln_scanner = vuln_scanner
        self._sbom_store = sbom_store
        self._dependency_graph = dependency_graph
        self._remediation_engine = remediation_engine
        self._repository = repository
        self._metrics: list[dict[str, Any]] = []

    # ---- Dependency Inventory ----

    async def inventory_dependencies(
        self,
        tenant_id: str = "",
        scope: str | None = None,
    ) -> list[DependencyRecord]:
        """Inventory all dependencies in the software supply chain."""
        records: list[DependencyRecord] = []
        now = datetime.now(UTC)

        if self._package_registry is not None:
            try:
                raw = await self._package_registry.list(
                    tenant_id=tenant_id,
                    scope=scope,
                )
                for item in raw:
                    records.append(
                        DependencyRecord(
                            record_id=item.get(
                                "id",
                                f"dep-{uuid4().hex[:8]}",
                            ),
                            name=item.get("name", ""),
                            version=item.get("version", ""),
                            dependency_type=DependencyType(
                                item.get("type", "direct"),
                            ),
                            source=item.get("source", ""),
                            license_type=item.get("license", ""),
                            maintainer=item.get("maintainer", ""),
                            last_updated=item.get(
                                "last_updated",
                                now,
                            ),
                            is_pinned=item.get("pinned", False),
                            depth=item.get("depth", 0),
                        )
                    )
            except Exception as e:
                logger.error(
                    "scre_inventory_failed",
                    error=str(e),
                )
        else:
            # Mock dependency inventory
            dep_types = list(DependencyType)
            names = [
                "requests",
                "flask",
                "django",
                "numpy",
                "cryptography",
                "boto3",
                "pydantic",
                "sqlalchemy",
                "celery",
                "redis-py",
                "grpcio",
                "protobuf",
            ]
            licenses = [
                "MIT",
                "Apache-2.0",
                "BSD-3",
                "GPL-3.0",
                "ISC",
            ]
            maintainers = [
                "pypi-team",
                "community",
                "corp-internal",
                "unknown",
            ]
            count = random.randint(20, 50)  # noqa: S311
            for _i in range(count):
                age = random.randint(1, 730)  # noqa: S311
                updated = now - timedelta(days=age)
                records.append(
                    DependencyRecord(
                        record_id=f"dep-{uuid4().hex[:8]}",
                        name=random.choice(names),  # noqa: S311
                        version=f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(0, 10)}",  # noqa: S311, E501
                        dependency_type=random.choice(  # noqa: S311
                            dep_types,
                        ),
                        source=random.choice(  # noqa: S311
                            ["pypi", "npm", "dockerhub", "internal"],
                        ),
                        license_type=random.choice(  # noqa: S311
                            licenses,
                        ),
                        maintainer=random.choice(  # noqa: S311
                            maintainers,
                        ),
                        last_updated=updated,
                        is_pinned=random.random() > 0.4,  # noqa: S311
                        depth=random.randint(0, 5),  # noqa: S311
                    )
                )

        logger.info(
            "scre_dependencies_inventoried",
            tenant_id=tenant_id,
            count=len(records),
        )
        return records

    # ---- Vulnerability Scanning ----

    async def scan_vulnerabilities(
        self,
        dependencies: list[DependencyRecord],
    ) -> list[VulnerabilityScan]:
        """Scan dependencies for known vulnerabilities."""
        scans: list[VulnerabilityScan] = []

        if self._vuln_scanner is not None:
            try:
                for dep in dependencies:
                    raw = await self._vuln_scanner.scan(
                        name=dep.name,
                        version=dep.version,
                    )
                    for vuln in raw:
                        scans.append(
                            VulnerabilityScan(
                                scan_id=f"vs-{uuid4().hex[:8]}",
                                record_id=dep.record_id,
                                cve_id=vuln.get("cve_id", ""),
                                severity=vuln.get(
                                    "severity",
                                    "medium",
                                ),
                                cvss_score=vuln.get("cvss", 0.0),
                                description=vuln.get("desc", ""),
                                fix_available=vuln.get("fix", False),
                                fix_version=vuln.get(
                                    "fix_version",
                                    "",
                                ),
                                exploitable=vuln.get(
                                    "exploitable",
                                    False,
                                ),
                            )
                        )
            except Exception as e:
                logger.error(
                    "scre_scan_failed",
                    error=str(e),
                )
        else:
            # Mock vulnerability scan
            severities = ["critical", "high", "medium", "low"]
            for dep in dependencies:
                vuln_count = random.randint(0, 3)  # noqa: S311
                for _j in range(vuln_count):
                    sev = random.choice(severities)  # noqa: S311
                    cvss_map = {
                        "critical": random.uniform(9.0, 10.0),  # noqa: S311
                        "high": random.uniform(7.0, 8.9),  # noqa: S311
                        "medium": random.uniform(4.0, 6.9),  # noqa: S311
                        "low": random.uniform(0.1, 3.9),  # noqa: S311
                    }
                    scans.append(
                        VulnerabilityScan(
                            scan_id=f"vs-{uuid4().hex[:8]}",
                            record_id=dep.record_id,
                            cve_id=f"CVE-2024-{random.randint(10000, 99999)}",  # noqa: S311
                            severity=sev,
                            cvss_score=round(
                                cvss_map.get(sev, 5.0),
                                1,
                            ),
                            description=f"Vuln in {dep.name}",
                            fix_available=random.random() > 0.3,  # noqa: S311
                            fix_version=f"{random.randint(1, 5)}.{random.randint(0, 20)}.{random.randint(1, 10)}",  # noqa: S311, E501
                            exploitable=random.random() > 0.6,  # noqa: S311
                        )
                    )

        logger.info(
            "scre_vulnerabilities_scanned",
            dependencies=len(dependencies),
            vulnerabilities=len(scans),
        )
        return scans

    # ---- Risk Assessment ----

    async def assess_risk(
        self,
        dependencies: list[DependencyRecord],
        scans: list[VulnerabilityScan],
    ) -> list[RiskAssessment]:
        """Assess risk for each dependency based on scans."""
        assessments: list[RiskAssessment] = []

        # Group scans by record
        by_record: dict[str, list[VulnerabilityScan]] = {}
        for scan in scans:
            by_record.setdefault(scan.record_id, []).append(scan)

        severity_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.2,
        }

        for dep in dependencies:
            dep_scans = by_record.get(dep.record_id, [])
            vuln_count = len(dep_scans)
            exploitable = sum(1 for s in dep_scans if s.exploitable)

            if not dep_scans:
                score = 0.1
                risk_level = SupplyChainRisk.LOW
            else:
                weighted = sum(severity_weights.get(s.severity, 0.3) for s in dep_scans)
                score = min(
                    round(weighted / max(vuln_count, 1), 3),
                    1.0,
                )
                if score > 0.8:
                    risk_level = SupplyChainRisk.CRITICAL
                elif score > 0.6:
                    risk_level = SupplyChainRisk.HIGH
                elif score > 0.3:
                    risk_level = SupplyChainRisk.MEDIUM
                else:
                    risk_level = SupplyChainRisk.LOW

            factors: list[str] = []
            if exploitable > 0:
                factors.append(f"{exploitable} exploitable vulns")
            if not dep.is_pinned:
                factors.append("unpinned version")
            if dep.maintainer == "unknown":
                factors.append("unknown maintainer")

            assessments.append(
                RiskAssessment(
                    assessment_id=f"ra-{uuid4().hex[:8]}",
                    record_id=dep.record_id,
                    risk_level=risk_level,
                    overall_score=score,
                    vulnerability_count=vuln_count,
                    exploitable_count=exploitable,
                    factors=factors,
                )
            )

        logger.info(
            "scre_risk_assessed",
            dependencies=len(dependencies),
            assessments=len(assessments),
        )
        return assessments

    # ---- Blast Radius Mapping ----

    async def map_blast_radius(
        self,
        assessments: list[RiskAssessment],
    ) -> list[BlastRadiusMapping]:
        """Map blast radius for risky dependencies."""
        mappings: list[BlastRadiusMapping] = []

        services = [
            "api-gateway",
            "auth-service",
            "data-pipeline",
            "web-frontend",
            "billing-svc",
            "notification-svc",
            "worker-pool",
        ]
        environments = ["production", "staging", "development"]

        for assessment in assessments:
            if assessment.risk_level in (
                SupplyChainRisk.LOW,
                SupplyChainRisk.INFORMATIONAL,
            ):
                continue

            svc_count = random.randint(1, 5)  # noqa: S311
            affected_svcs = random.sample(  # noqa: S311
                services,
                min(svc_count, len(services)),
            )
            env_count = random.randint(1, 3)  # noqa: S311
            affected_envs = random.sample(  # noqa: S311
                environments,
                min(env_count, len(environments)),
            )
            downstream = random.randint(0, 15)  # noqa: S311

            if downstream > 10:
                blast = "critical"
            elif downstream > 5:
                blast = "high"
            elif downstream > 2:
                blast = "medium"
            else:
                blast = "low"

            mappings.append(
                BlastRadiusMapping(
                    mapping_id=f"br-{uuid4().hex[:8]}",
                    record_id=assessment.record_id,
                    affected_services=affected_svcs,
                    affected_environments=affected_envs,
                    downstream_count=downstream,
                    blast_radius=blast,
                )
            )

        logger.info(
            "scre_blast_radius_mapped",
            assessments=len(assessments),
            mappings=len(mappings),
        )
        return mappings

    # ---- Mitigation Recommendations ----

    async def recommend_mitigations(
        self,
        assessments: list[RiskAssessment],
        mappings: list[BlastRadiusMapping],
    ) -> list[MitigationRecommendation]:
        """Generate mitigation recommendations."""
        recommendations: list[MitigationRecommendation] = []

        mapping_map: dict[str, BlastRadiusMapping] = {m.record_id: m for m in mappings}

        for assessment in assessments:
            if assessment.risk_level in (
                SupplyChainRisk.LOW,
                SupplyChainRisk.INFORMATIONAL,
            ):
                continue

            mapping = mapping_map.get(assessment.record_id)
            if mapping and mapping.blast_radius in (
                "critical",
                "high",
            ):
                priority = "critical"
            elif assessment.overall_score > 0.7:
                priority = "high"
            else:
                priority = "medium"

            automated = random.random() > 0.4  # noqa: S311
            effort = random.choice(  # noqa: S311
                ["low", "medium", "high"],
            )

            action = "upgrade_dependency"
            if assessment.exploitable_count > 0:
                action = "patch_or_replace"
            if "unpinned" in " ".join(assessment.factors):
                action = "pin_version"

            recommendations.append(
                MitigationRecommendation(
                    recommendation_id=(f"mit-{uuid4().hex[:8]}"),
                    record_id=assessment.record_id,
                    priority=priority,
                    action=action,
                    description=(
                        f"Mitigate {assessment.risk_level.value} "
                        f"risk: {', '.join(assessment.factors)}"
                    ),
                    effort=effort,
                    automated=automated,
                )
            )

        logger.info(
            "scre_mitigations_recommended",
            assessments=len(assessments),
            recommendations=len(recommendations),
        )
        return recommendations

    # ---- Metrics ----

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> None:
        """Record a supply chain risk engine metric."""
        self._metrics.append(
            {
                "name": metric_name,
                "value": value,
                "tags": tags or {},
                "timestamp": datetime.now(UTC).isoformat(),
            }
        )
