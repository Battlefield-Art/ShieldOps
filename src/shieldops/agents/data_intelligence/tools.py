"""Data Intelligence Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    AIClassification,
    DataDiscovery,
    DataDomain,
    DataLineage,
    DataRisk,
    ProtectionPlan,
    ProtectionRecommendation,
)

logger = structlog.get_logger()

_DATA_PROFILES: list[dict[str, Any]] = [
    {
        "name": "customer_db",
        "domain": DataDomain.STRUCTURED,
        "size": 250.0,
        "records": 5000000,
        "pii": True,
    },
    {
        "name": "training_corpus",
        "domain": DataDomain.AI_TRAINING,
        "size": 1200.0,
        "records": 10000000,
        "pii": False,
    },
    {
        "name": "embeddings_store",
        "domain": DataDomain.EMBEDDING,
        "size": 80.0,
        "records": 2000000,
        "pii": False,
    },
    {
        "name": "model_registry",
        "domain": DataDomain.MODEL_ARTIFACT,
        "size": 500.0,
        "records": 150,
        "pii": False,
    },
    {
        "name": "audit_logs",
        "domain": DataDomain.SEMI_STRUCTURED,
        "size": 45.0,
        "records": 50000000,
        "pii": True,
    },
    {
        "name": "support_tickets",
        "domain": DataDomain.UNSTRUCTURED,
        "size": 30.0,
        "records": 200000,
        "pii": True,
    },
    {
        "name": "medical_records",
        "domain": DataDomain.STRUCTURED,
        "size": 120.0,
        "records": 1000000,
        "pii": True,
    },
    {
        "name": "payment_data",
        "domain": DataDomain.STRUCTURED,
        "size": 60.0,
        "records": 3000000,
        "pii": True,
    },
]

_FRAMEWORKS = [
    "GDPR",
    "HIPAA",
    "PCI-DSS",
    "SOC2",
    "CCPA",
]

_SYSTEMS = [
    "postgres-prod",
    "s3-data-lake",
    "kafka-stream",
    "redis-cache",
    "snowflake-dw",
    "bigquery",
]


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class DataIntelligenceToolkit:
    """Tools for data intelligence analysis."""

    def __init__(
        self,
        catalog_client: Any | None = None,
        classifier: Any | None = None,
        lineage_api: Any | None = None,
    ) -> None:
        self._catalog = catalog_client
        self._classifier = classifier
        self._lineage_api = lineage_api

    async def discover_data(self, tenant_id: str) -> list[DataDiscovery]:
        """Discover data sources."""
        logger.info(
            "data_intel.discover",
            tenant_id=tenant_id,
        )

        if self._catalog is not None:
            try:
                raw = await self._catalog.scan(tenant_id=tenant_id)
                return [DataDiscovery(**d) for d in raw]
            except Exception:
                logger.exception("data_intel.discover.error")

        sources: list[DataDiscovery] = []
        for i, prof in enumerate(_DATA_PROFILES):
            sources.append(
                DataDiscovery(
                    id=_gen_id("DS", tenant_id, i),
                    name=prof["name"],
                    domain=prof["domain"],
                    location=random.choice(  # noqa: S311
                        [
                            "us-east-1",
                            "eu-west-1",
                            "ap-south-1",
                        ]
                    ),
                    size_gb=prof["size"],
                    record_count=prof["records"],
                    owner=f"team-data-{i}",
                    last_accessed=("2026-03-25T08:00:00Z"),
                    encrypted=random.choice(  # noqa: S311
                        [True, True, False]
                    ),
                )
            )
        return sources

    async def classify_with_ai(self, sources: list[DataDiscovery]) -> list[AIClassification]:
        """Classify data sources with AI."""
        logger.info(
            "data_intel.classify",
            count=len(sources),
        )

        if self._classifier is not None:
            try:
                raw = await self._classifier.classify([s.id for s in sources])
                return [AIClassification(**c) for c in raw]
            except Exception:
                logger.exception("data_intel.classify.error")

        results: list[AIClassification] = []
        for src in sources:
            pii = src.name in (
                "customer_db",
                "audit_logs",
                "support_tickets",
                "medical_records",
                "payment_data",
            )
            phi = src.name == "medical_records"
            pci = src.name == "payment_data"

            frameworks: list[str] = []
            if pii:
                frameworks.extend(["GDPR", "CCPA"])
            if phi:
                frameworks.append("HIPAA")
            if pci:
                frameworks.append("PCI-DSS")

            sens = (
                "critical"
                if phi or pci
                else "high"
                if pii
                else "medium"
                if src.domain == DataDomain.AI_TRAINING
                else "low"
            )

            results.append(
                AIClassification(
                    data_id=src.id,
                    sensitivity_level=sens,
                    data_types=[src.domain.value],
                    pii_detected=pii,
                    phi_detected=phi,
                    pci_detected=pci,
                    confidence=round(
                        random.uniform(  # noqa: S311
                            0.7, 0.99
                        ),
                        2,
                    ),
                    regulatory_frameworks=(frameworks),
                )
            )
        return results

    async def map_lineage(self, sources: list[DataDiscovery]) -> list[DataLineage]:
        """Map data lineage for each source."""
        logger.info(
            "data_intel.lineage",
            count=len(sources),
        )

        if self._lineage_api is not None:
            try:
                raw = await self._lineage_api.trace([s.id for s in sources])
                return [DataLineage(**lineage_item) for lineage_item in raw]
            except Exception:
                logger.exception("data_intel.lineage.error")

        results: list[DataLineage] = []
        for src in sources:
            upstream = random.sample(  # noqa: S311
                _SYSTEMS,
                k=random.randint(1, 3),  # noqa: S311
            )
            downstream = random.sample(  # noqa: S311
                _SYSTEMS,
                k=random.randint(1, 3),  # noqa: S311
            )
            cross = src.location != "us-east-1"
            results.append(
                DataLineage(
                    data_id=src.id,
                    source_systems=upstream,
                    downstream_consumers=downstream,
                    transformations=[
                        "etl_pipeline",
                        "anonymization",
                    ],
                    retention_days=random.choice(  # noqa: S311
                        [90, 365, 730, 2190]
                    ),
                    cross_border=cross,
                )
            )
        return results

    async def assess_risk(
        self,
        sources: list[DataDiscovery],
        classifications: list[AIClassification],
        lineages: list[DataLineage],
    ) -> list[DataRisk]:
        """Assess data risk for each source."""
        logger.info(
            "data_intel.risk",
            count=len(sources),
        )

        class_map = {c.data_id: c for c in classifications}
        lineage_map = {lineage_item.data_id: lineage_item for lineage_item in lineages}

        results: list[DataRisk] = []
        for src in sources:
            cl = class_map.get(src.id)
            ln = lineage_map.get(src.id)

            base_risk = 3.0
            if cl and cl.pii_detected:
                base_risk += 2.0
            if cl and cl.phi_detected:
                base_risk += 2.5
            if cl and cl.pci_detected:
                base_risk += 2.0
            if not src.encrypted:
                base_risk += 1.5
            if ln and ln.cross_border:
                base_risk += 1.0

            risk = round(min(10.0, base_risk), 1)
            gaps: list[str] = []
            if cl:
                for fw in cl.regulatory_frameworks:
                    if random.random() < 0.3:  # noqa: S311
                        gaps.append(f"{fw} non-compliant")

            results.append(
                DataRisk(
                    data_id=src.id,
                    risk_score=risk,
                    exposure_type=("internet" if not src.encrypted else "internal"),
                    access_violations=random.randint(  # noqa: S311
                        0, 10
                    ),
                    stale_permissions=random.randint(  # noqa: S311
                        0, 20
                    ),
                    compliance_gaps=gaps,
                    threat_vectors=[
                        "data_exfiltration",
                        "unauthorized_access",
                    ],
                )
            )
        return results

    async def recommend_protection(
        self,
        sources: list[DataDiscovery],
        risks: list[DataRisk],
        classifications: list[AIClassification],
    ) -> list[ProtectionPlan]:
        """Generate protection recommendations."""
        logger.info(
            "data_intel.protect",
            count=len(sources),
        )

        risk_map = {r.data_id: r for r in risks}
        class_map = {c.data_id: c for c in classifications}
        {s.id: s for s in sources}

        plans: list[ProtectionPlan] = []
        for src in sources:
            risk = risk_map.get(src.id)
            cl = class_map.get(src.id)
            if not risk:
                continue

            recs: list[ProtectionRecommendation] = []
            if not src.encrypted:
                recs.append(ProtectionRecommendation.ENCRYPT)
            if cl and cl.pii_detected:
                recs.append(ProtectionRecommendation.MASK)
            if risk.access_violations > 5:
                recs.append(ProtectionRecommendation.RESTRICT_ACCESS)
            if risk.risk_score >= 8.0:
                recs.append(ProtectionRecommendation.IMMUTABLE_LOCK)
            if not recs:
                recs.append(ProtectionRecommendation.BACKUP)

            priority = (
                "critical"
                if risk.risk_score >= 8.0
                else "high"
                if risk.risk_score >= 6.0
                else "medium"
                if risk.risk_score >= 4.0
                else "low"
            )

            plans.append(
                ProtectionPlan(
                    data_id=src.id,
                    data_name=src.name,
                    risk_score=risk.risk_score,
                    recommendations=recs,
                    priority=priority,
                    estimated_effort_hours=round(
                        random.uniform(  # noqa: S311
                            2.0, 40.0
                        ),
                        1,
                    ),
                    rationale=(
                        f"Risk {risk.risk_score}/10, {len(risk.compliance_gaps)} compliance gaps"
                    ),
                )
            )
        return plans
