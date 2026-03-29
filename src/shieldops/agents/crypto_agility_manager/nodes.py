"""Crypto Agility Manager Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    AgilityAssessment,
    AlgorithmRecord,
    CompatibilityResult,
    MigrationPlan,
    MigrationStage,
)
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AgilityAnalysisResult,
    CryptoReportResult,
    MigrationPlanResult,
)
from .tools import CryptoAgilityManagerToolkit

logger = structlog.get_logger()


async def discover_algorithms(
    state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit
) -> dict[str, Any]:
    """Discover all cryptographic algorithms across infrastructure."""
    logger.info("crypto_agility.node.discover_algorithms")

    tenant_id = state.get("tenant_id", "")
    algorithms = await toolkit.discover_algorithms(tenant_id)
    algo_data = [a.model_dump(mode="json") for a in algorithms]

    quantum_vulnerable = sum(1 for a in algorithms if not a.quantum_safe)

    return {
        "current_step": "discover_algorithms",
        "stage": MigrationStage.ASSESS_AGILITY.value,
        "algorithms": algo_data,
        "total_algorithms": len(algorithms),
        "quantum_vulnerable_count": quantum_vulnerable,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Discovered {len(algorithms)} algorithms, {quantum_vulnerable} quantum-vulnerable"],
    }


async def assess_agility(
    state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit
) -> dict[str, Any]:
    """Assess cryptographic agility for each service."""
    logger.info("crypto_agility.node.assess_agility")

    raw_algos = state.get("algorithms", [])
    algorithms = [AlgorithmRecord(**a) for a in raw_algos]
    assessments = await toolkit.assess_agility(algorithms)
    assessments_data = [a.model_dump() for a in assessments]

    reasoning_note = f"Assessed {len(assessments)} services for cryptographic agility"

    if assessments:
        try:
            context = json.dumps(
                {
                    "total_algorithms": len(algorithms),
                    "assessments": [
                        {
                            "service": a.service,
                            "algorithm": a.algorithm,
                            "supports_hybrid": a.supports_hybrid,
                            "migration_complexity": a.migration_complexity,
                            "recommended_pqc": a.recommended_pqc,
                            "blockers": a.blockers,
                        }
                        for a in assessments
                    ],
                },
                default=str,
            )
            result = cast(
                AgilityAnalysisResult,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE,
                    user_prompt=f"Agility assessment context:\n{context}",
                    schema=AgilityAnalysisResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="crypto_agility", node="assess_agility")

    return {
        "current_step": "assess_agility",
        "stage": MigrationStage.PLAN_MIGRATION.value,
        "assessments": assessments_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def plan_migration(
    state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit
) -> dict[str, Any]:
    """Create PQC migration plans based on assessments."""
    logger.info("crypto_agility.node.plan_migration")

    raw_assessments = state.get("assessments", [])
    raw_algos = state.get("algorithms", [])
    assessments = [AgilityAssessment(**a) for a in raw_assessments]
    algorithms = [AlgorithmRecord(**a) for a in raw_algos]

    plans = await toolkit.plan_migration(assessments, algorithms)
    plans_data = [p.model_dump() for p in plans]

    reasoning_note = f"Created {len(plans)} PQC migration plans"

    if plans:
        try:
            context = json.dumps(
                {
                    "plans": [
                        {
                            "service": p.service,
                            "current": p.current_algorithm,
                            "target": p.target_algorithm,
                            "priority": p.priority.value,
                            "hybrid": p.hybrid_mode,
                        }
                        for p in plans
                    ],
                },
                default=str,
            )
            result = cast(
                MigrationPlanResult,
                await llm_structured(
                    system_prompt=SYSTEM_ANALYZE,
                    user_prompt=f"Migration plan context:\n{context}",
                    schema=MigrationPlanResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="crypto_agility", node="plan_migration")

    return {
        "current_step": "plan_migration",
        "stage": MigrationStage.TEST_COMPATIBILITY.value,
        "migration_plans": plans_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def test_compatibility(
    state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit
) -> dict[str, Any]:
    """Test PQC algorithm compatibility for each migration plan."""
    logger.info("crypto_agility.node.test_compatibility")

    raw_plans = state.get("migration_plans", [])
    plans = [MigrationPlan(**p) for p in raw_plans]

    results = await toolkit.test_compatibility(plans)
    results_data = [r.model_dump() for r in results]

    compatible_count = sum(1 for r in results if r.compatible)
    incompatible_count = len(results) - compatible_count

    return {
        "current_step": "test_compatibility",
        "stage": MigrationStage.EXECUTE_MIGRATION.value,
        "compatibility_results": results_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Tested {len(results)} migrations: {compatible_count} compatible, "
            f"{incompatible_count} have issues"
        ],
    }


async def execute_migration(
    state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit
) -> dict[str, Any]:
    """Execute PQC migrations."""
    logger.info("crypto_agility.node.execute_migration")

    raw_plans = state.get("migration_plans", [])
    raw_compat = state.get("compatibility_results", [])
    compat_map = {CompatibilityResult(**c).service: CompatibilityResult(**c) for c in raw_compat}

    executions: list[dict[str, Any]] = []
    migrated = 0

    for raw in raw_plans:
        plan = MigrationPlan(**raw)
        compat = compat_map.get(plan.service)
        compatible = compat.compatible if compat else True

        result = await toolkit.execute_migration(plan, compatible=compatible)
        executions.append(result.model_dump())
        if result.status == "completed":
            migrated += 1

    return {
        "current_step": "execute_migration",
        "stage": MigrationStage.REPORT.value,
        "executions": executions,
        "migrated_count": migrated,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Executed {len(executions)} migrations, {migrated} completed"],
    }


async def report(state: dict[str, Any], toolkit: CryptoAgilityManagerToolkit) -> dict[str, Any]:
    """Generate crypto agility management report."""
    logger.info("crypto_agility.node.report")

    total = state.get("total_algorithms", 0)
    vulnerable = state.get("quantum_vulnerable_count", 0)
    migrated = state.get("migrated_count", 0)
    summary = (
        f"Crypto agility scan: {total} algorithms inventoried, "
        f"{vulnerable} quantum-vulnerable, {migrated} migrated to PQC"
    )

    try:
        context = json.dumps(
            {
                "total_algorithms": total,
                "quantum_vulnerable_count": vulnerable,
                "migrated_count": migrated,
                "algorithms": state.get("algorithms", [])[:10],
                "assessments": state.get("assessments", [])[:10],
                "compatibility_results": state.get("compatibility_results", [])[:10],
                "executions": state.get("executions", [])[:10],
            },
            default=str,
        )
        result = cast(
            CryptoReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Report context:\n{context}",
                schema=CryptoReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="crypto_agility", node="report")

    return {
        "current_step": "report",
        "stage": MigrationStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
