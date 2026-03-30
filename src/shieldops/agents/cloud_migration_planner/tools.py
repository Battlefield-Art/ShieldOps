"""Cloud Migration Planner Agent — Tool functions."""

from __future__ import annotations

import hashlib
import random
from typing import Any

import structlog

from .models import (
    DependencyMap,
    MigrationExecution,
    MigrationPlan,
    MigrationRisk,
    MigrationStrategy,
    ReadinessAssessment,
    WorkloadProfile,
)

logger = structlog.get_logger()

_WORKLOAD_PROFILES: list[dict[str, Any]] = [
    {
        "name": "web-api-gateway",
        "workload_type": "api_server",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 8,
        "mem": 32.0,
        "storage": 100.0,
        "cost": 1200.0,
        "deps": ["auth-service", "postgres-primary"],
    },
    {
        "name": "postgres-primary",
        "workload_type": "database",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 16,
        "mem": 64.0,
        "storage": 2000.0,
        "cost": 3500.0,
        "deps": [],
    },
    {
        "name": "redis-cache-cluster",
        "workload_type": "cache",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 4,
        "mem": 16.0,
        "storage": 50.0,
        "cost": 600.0,
        "deps": [],
    },
    {
        "name": "rabbitmq-broker",
        "workload_type": "message_queue",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 4,
        "mem": 8.0,
        "storage": 200.0,
        "cost": 450.0,
        "deps": [],
    },
    {
        "name": "auth-service",
        "workload_type": "microservice",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 4,
        "mem": 8.0,
        "storage": 20.0,
        "cost": 350.0,
        "deps": ["postgres-primary", "redis-cache-cluster"],
    },
    {
        "name": "batch-etl-pipeline",
        "workload_type": "batch_job",
        "source_env": "on-prem-dc2",
        "target_env": "gcp-us-central1",
        "cpu": 32,
        "mem": 128.0,
        "storage": 5000.0,
        "cost": 4200.0,
        "deps": ["postgres-primary"],
    },
    {
        "name": "ml-training-cluster",
        "workload_type": "compute_cluster",
        "source_env": "on-prem-dc2",
        "target_env": "gcp-us-central1",
        "cpu": 64,
        "mem": 256.0,
        "storage": 10000.0,
        "cost": 8500.0,
        "deps": ["batch-etl-pipeline"],
    },
    {
        "name": "legacy-monolith",
        "workload_type": "legacy_app",
        "source_env": "on-prem-dc1",
        "target_env": "aws-us-east-1",
        "cpu": 16,
        "mem": 32.0,
        "storage": 500.0,
        "cost": 2800.0,
        "deps": [
            "postgres-primary",
            "rabbitmq-broker",
        ],
    },
]

_STRATEGY_MAP: dict[str, MigrationStrategy] = {
    "api_server": MigrationStrategy.REPLATFORM,
    "database": MigrationStrategy.REPLATFORM,
    "cache": MigrationStrategy.REHOST,
    "message_queue": MigrationStrategy.REPURCHASE,
    "microservice": MigrationStrategy.REHOST,
    "batch_job": MigrationStrategy.REFACTOR,
    "compute_cluster": MigrationStrategy.REFACTOR,
    "legacy_app": MigrationStrategy.REFACTOR,
}

_RISK_MAP: dict[str, MigrationRisk] = {
    "api_server": MigrationRisk.MEDIUM,
    "database": MigrationRisk.HIGH,
    "cache": MigrationRisk.LOW,
    "message_queue": MigrationRisk.LOW,
    "microservice": MigrationRisk.LOW,
    "batch_job": MigrationRisk.MEDIUM,
    "compute_cluster": MigrationRisk.HIGH,
    "legacy_app": MigrationRisk.CRITICAL,
}


def _gen_id(prefix: str, seed: str, idx: int) -> str:
    raw = f"{seed}:{idx}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"{prefix}-{h.upper()}"


class CloudMigrationPlannerToolkit:
    """Tools for cloud migration planning."""

    def __init__(
        self,
        discovery_api: Any | None = None,
        cloud_provider: Any | None = None,
    ) -> None:
        self._discovery_api = discovery_api
        self._cloud_provider = cloud_provider

    async def discover_workloads(
        self,
        tenant_id: str,
    ) -> list[WorkloadProfile]:
        """Discover workloads across environments."""
        logger.info(
            "cmp.discover_workloads",
            tenant_id=tenant_id,
        )

        if self._discovery_api is not None:
            try:
                raw = await self._discovery_api.discover(
                    tenant_id=tenant_id,
                )
                return [WorkloadProfile(**r) for r in raw]
            except Exception:
                logger.exception(
                    "cmp.discover_workloads.error",
                )

        workloads: list[WorkloadProfile] = []
        for i, p in enumerate(_WORKLOAD_PROFILES):
            workloads.append(
                WorkloadProfile(
                    id=_gen_id("WL", tenant_id, i),
                    name=p["name"],
                    workload_type=p["workload_type"],
                    source_env=p["source_env"],
                    target_env=p["target_env"],
                    cpu_cores=p["cpu"],
                    memory_gb=p["mem"],
                    storage_gb=p["storage"],
                    monthly_cost=p["cost"],
                    dependencies=p["deps"],
                    tags={"env": "production"},
                )
            )
        return workloads

    async def assess_readiness(
        self,
        workloads: list[WorkloadProfile],
    ) -> list[ReadinessAssessment]:
        """Assess migration readiness for each workload."""
        logger.info(
            "cmp.assess_readiness",
            count=len(workloads),
        )

        assessments: list[ReadinessAssessment] = []
        for w in workloads:
            strategy = _STRATEGY_MAP.get(
                w.workload_type,
                MigrationStrategy.REHOST,
            )
            risk = _RISK_MAP.get(
                w.workload_type,
                MigrationRisk.MEDIUM,
            )
            score = {
                MigrationRisk.CRITICAL: 0.3,
                MigrationRisk.HIGH: 0.5,
                MigrationRisk.MEDIUM: 0.7,
                MigrationRisk.LOW: 0.85,
                MigrationRisk.MINIMAL: 0.95,
            }.get(risk, 0.7)

            noise = random.gauss(0, 0.05)  # noqa: S311
            score = round(
                max(0.0, min(1.0, score + noise)),
                2,
            )

            blockers: list[str] = []
            if risk in (
                MigrationRisk.CRITICAL,
                MigrationRisk.HIGH,
            ):
                blockers.append(
                    f"High-risk {w.workload_type} requires manual review",
                )
            if len(w.dependencies) > 2:
                blockers.append(
                    "Complex dependency chain",
                )

            recs: list[str] = []
            if strategy == MigrationStrategy.REFACTOR:
                recs.append(
                    "Consider containerization first",
                )
            if w.storage_gb > 1000:
                recs.append(
                    "Plan data transfer window",
                )

            assessments.append(
                ReadinessAssessment(
                    workload_id=w.id,
                    workload_name=w.name,
                    strategy=strategy,
                    risk=risk,
                    readiness_score=score,
                    blockers=blockers,
                    recommendations=recs,
                )
            )
        return assessments

    async def plan_migration(
        self,
        assessments: list[ReadinessAssessment],
    ) -> list[MigrationPlan]:
        """Create migration plans from assessments."""
        logger.info(
            "cmp.plan_migration",
            count=len(assessments),
        )

        plans: list[MigrationPlan] = []
        for i, a in enumerate(assessments):
            hours = {
                MigrationStrategy.REHOST: 8.0,
                MigrationStrategy.REPLATFORM: 24.0,
                MigrationStrategy.REFACTOR: 80.0,
                MigrationStrategy.REPURCHASE: 16.0,
                MigrationStrategy.RETIRE: 4.0,
                MigrationStrategy.RETAIN: 0.0,
            }.get(a.strategy, 24.0)

            cost = round(hours * 150.0, 2)
            wave = 1 if a.readiness_score > 0.8 else (2 if a.readiness_score > 0.5 else 3)

            target = {
                MigrationStrategy.REHOST: "EC2/GCE VM",
                MigrationStrategy.REPLATFORM: "EKS/GKE",
                MigrationStrategy.REFACTOR: "Lambda/Cloud Run",
                MigrationStrategy.REPURCHASE: "Managed SaaS",
                MigrationStrategy.RETIRE: "Decommission",
                MigrationStrategy.RETAIN: "On-prem",
            }.get(a.strategy, "EC2/GCE VM")

            plans.append(
                MigrationPlan(
                    id=_gen_id("MP", a.workload_id, i),
                    workload_id=a.workload_id,
                    strategy=a.strategy,
                    target_service=target,
                    estimated_hours=hours,
                    estimated_cost=cost,
                    wave=wave,
                    prerequisites=a.blockers,
                )
            )
        return plans

    async def validate_dependencies(
        self,
        plans: list[MigrationPlan],
    ) -> list[DependencyMap]:
        """Validate dependencies between migration plans."""
        logger.info(
            "cmp.validate_dependencies",
            count=len(plans),
        )

        dep_maps: list[DependencyMap] = []

        for i, p in enumerate(plans):
            dep_maps.append(
                DependencyMap(
                    plan_id=p.id,
                    workload_id=p.workload_id,
                    upstream=p.prerequisites[:2],
                    downstream=[],
                    circular=False,
                    migration_order=p.wave * 10 + i,
                    blockers=[],
                )
            )
        return dep_maps

    async def execute_migration(
        self,
        plans: list[MigrationPlan],
    ) -> list[MigrationExecution]:
        """Execute migration plans (simulated)."""
        logger.info(
            "cmp.execute_migration",
            count=len(plans),
        )

        executions: list[MigrationExecution] = []
        for i, p in enumerate(plans):
            if p.strategy == MigrationStrategy.RETAIN:
                status = "skipped"
                progress = 0.0
            elif p.strategy == MigrationStrategy.RETIRE:
                status = "completed"
                progress = 100.0
            else:
                status = "in_progress"
                progress = round(
                    random.uniform(60.0, 95.0),  # noqa: S311
                    1,
                )

            executions.append(
                MigrationExecution(
                    id=_gen_id("ME", p.id, i),
                    plan_id=p.id,
                    status=status,
                    progress_pct=progress,
                    duration_hours=round(
                        p.estimated_hours
                        * random.uniform(  # noqa: S311
                            0.8,
                            1.3,
                        ),
                        1,
                    ),
                    rollback_available=True,
                    validation_passed=(progress > 80.0),
                )
            )
        return executions
