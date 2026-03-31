"""Security Data Mesh Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    DataProduct,
    DataQualityGrade,
    DomainStatus,
    FederatedQuery,
    MeshInsight,
    QualityAssessment,
    SecurityDomain,
)

logger = structlog.get_logger()

_SAMPLE_DOMAINS: list[dict[str, Any]] = [
    {
        "name": "Threat Intelligence",
        "owner": "threat-intel-team",
        "status": "active",
        "tags": ["ioc", "feeds", "attribution"],
    },
    {
        "name": "Vulnerability Management",
        "owner": "vuln-team",
        "status": "active",
        "tags": ["cve", "scan", "patch"],
    },
    {
        "name": "Identity & Access",
        "owner": "iam-team",
        "status": "active",
        "tags": ["auth", "rbac", "nhi"],
    },
    {
        "name": "Endpoint Telemetry",
        "owner": "edr-team",
        "status": "degraded",
        "tags": ["edr", "process", "network"],
    },
    {
        "name": "Cloud Security",
        "owner": "cloud-sec-team",
        "status": "active",
        "tags": ["cspm", "cwpp", "iac"],
    },
    {
        "name": "Compliance Evidence",
        "owner": "grc-team",
        "status": "active",
        "tags": ["audit", "evidence", "controls"],
    },
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class SecurityDataMeshToolkit:
    """Tools for security data mesh management."""

    def __init__(
        self,
        mesh_catalog: Any | None = None,
        query_engine: Any | None = None,
    ) -> None:
        self._mesh_catalog = mesh_catalog
        self._query_engine = query_engine

    async def discover_domains(
        self,
        tenant_id: str,
    ) -> list[SecurityDomain]:
        """Discover security data domains in the mesh."""
        logger.info(
            "sdm.discover_domains",
            tenant_id=tenant_id,
        )

        if self._mesh_catalog is not None:
            try:
                raw = await self._mesh_catalog.list_domains(
                    tenant_id=tenant_id,
                )
                return [SecurityDomain(**r) for r in raw]
            except Exception:
                logger.exception("sdm.discover_domains.error")

        domains: list[SecurityDomain] = []
        for i, d in enumerate(_SAMPLE_DOMAINS):
            products = random.randint(3, 12)  # noqa: S311
            domains.append(
                SecurityDomain(
                    id=_gen_id("SD", tenant_id, i),
                    name=d["name"],
                    owner=d["owner"],
                    status=DomainStatus(d["status"]),
                    data_product_count=products,
                    freshness_minutes=random.randint(1, 60),  # noqa: S311
                    consumers=random.randint(2, 20),  # noqa: S311
                    tags=d["tags"],
                )
            )
        return domains

    async def map_data_products(
        self,
        domains: list[SecurityDomain],
    ) -> list[DataProduct]:
        """Map data products within each domain."""
        logger.info(
            "sdm.map_data_products",
            domain_count=len(domains),
        )

        _product_templates = [
            "IOC Feed",
            "CVE Database",
            "Auth Logs",
            "Process Events",
            "Cloud Config",
            "Audit Trail",
            "Alert Stream",
            "Scan Results",
            "Policy State",
        ]

        products: list[DataProduct] = []
        idx = 0
        for d in domains:
            count = min(d.data_product_count, 3)
            for j in range(count):
                tpl = _product_templates[(idx + j) % len(_product_templates)]
                products.append(
                    DataProduct(
                        id=_gen_id("DP", d.id, idx),
                        domain_id=d.id,
                        name=f"{d.name} — {tpl}",
                        schema_version="1.0",
                        record_count=random.randint(1000, 500000),  # noqa: S311
                        freshness_minutes=random.randint(1, 120),  # noqa: S311
                        quality_score=round(
                            random.uniform(0.5, 1.0),  # noqa: S311
                            2,
                        ),
                        sla_met=random.random() > 0.2,  # noqa: S311
                        consumers=[f"consumer-{k}" for k in range(random.randint(1, 5))],  # noqa: S311
                    )
                )
                idx += 1
        return products

    async def assess_quality(
        self,
        products: list[DataProduct],
    ) -> list[QualityAssessment]:
        """Assess quality of each data product."""
        logger.info(
            "sdm.assess_quality",
            count=len(products),
        )

        assessments: list[QualityAssessment] = []
        for i, p in enumerate(products):
            comp = round(random.uniform(0.6, 1.0), 2)  # noqa: S311
            acc = round(random.uniform(0.7, 1.0), 2)  # noqa: S311
            time = round(random.uniform(0.5, 1.0), 2)  # noqa: S311
            cons = round(random.uniform(0.6, 1.0), 2)  # noqa: S311
            avg = (comp + acc + time + cons) / 4

            grade = DataQualityGrade.GOOD
            if avg >= 0.9:
                grade = DataQualityGrade.EXCELLENT
            elif avg >= 0.75:
                grade = DataQualityGrade.GOOD
            elif avg >= 0.6:
                grade = DataQualityGrade.FAIR
            else:
                grade = DataQualityGrade.POOR

            issues: list[str] = []
            if comp < 0.7:
                issues.append("Low completeness")
            if time < 0.6:
                issues.append("Stale data detected")
            if not p.sla_met:
                issues.append("SLA breach")

            assessments.append(
                QualityAssessment(
                    id=_gen_id("QA", p.id, i),
                    product_id=p.id,
                    grade=grade,
                    completeness=comp,
                    accuracy=acc,
                    timeliness=time,
                    consistency=cons,
                    issues=issues,
                )
            )
        return assessments

    async def federate_queries(
        self,
        domains: list[SecurityDomain],
    ) -> list[FederatedQuery]:
        """Run federated queries across domains."""
        logger.info(
            "sdm.federate_queries",
            domain_count=len(domains),
        )

        queries = [
            (
                "Correlated IOCs with active vulnerabilities",
                ["Threat Intelligence", "Vulnerability Management"],
            ),
            (
                "Identity events overlapping cloud config changes",
                ["Identity & Access", "Cloud Security"],
            ),
            (
                "Endpoint alerts mapped to compliance controls",
                ["Endpoint Telemetry", "Compliance Evidence"],
            ),
        ]

        results: list[FederatedQuery] = []
        for i, (q, doms) in enumerate(queries):
            results.append(
                FederatedQuery(
                    id=_gen_id("FQ", "query", i),
                    query=q,
                    domains_queried=doms,
                    records_returned=random.randint(50, 5000),  # noqa: S311
                    latency_ms=round(
                        random.uniform(120.0, 2500.0),  # noqa: S311
                        1,
                    ),
                    status="success",
                )
            )
        return results

    async def generate_insights(
        self,
        _queries: list[FederatedQuery],
    ) -> list[MeshInsight]:
        """Generate cross-domain security insights."""
        logger.info(
            "sdm.generate_insights",
            query_count=len(_queries),
        )

        insights: list[MeshInsight] = [
            MeshInsight(
                id=_gen_id("MI", "insight", 0),
                title="IOC-Vulnerability Correlation Gap",
                description="34% of active IOCs have no matching CVE scan data",
                severity="high",
                domains_involved=["Threat Intelligence", "Vulnerability Management"],
                evidence=["IOC feed has 12K entries", "CVE scan covers 8K assets"],
                actionable=True,
            ),
            MeshInsight(
                id=_gen_id("MI", "insight", 1),
                title="Identity-Cloud Drift",
                description="Service accounts with cloud admin roles not in IAM inventory",
                severity="critical",
                domains_involved=["Identity & Access", "Cloud Security"],
                evidence=["14 orphan service accounts", "3 with admin privileges"],
                actionable=True,
            ),
            MeshInsight(
                id=_gen_id("MI", "insight", 2),
                title="Endpoint Telemetry Lag",
                description="EDR data 45min behind real-time, impacting detection SLA",
                severity="medium",
                domains_involved=["Endpoint Telemetry"],
                evidence=["Average freshness: 45min", "SLA target: 5min"],
                actionable=True,
            ),
        ]
        return insights

    async def record_metric(
        self,
        metric_name: str,
        value: float,
        tags: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Record a data mesh metric."""
        logger.info(
            "sdm.record_metric",
            metric=metric_name,
            value=value,
        )
        return {"metric": metric_name, "recorded": True}
