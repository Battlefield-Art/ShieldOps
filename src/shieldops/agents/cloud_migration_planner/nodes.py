"""Cloud Migration Planner Agent — Node implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    CMPStage,
    MigrationPlan,
    ReadinessAssessment,
    ReasoningStep,
    WorkloadProfile,
)
from .tools import CloudMigrationPlannerToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Discover Workloads
# ------------------------------------------------------------------


async def discover_workloads(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Discover workloads across environments."""
    logger.info("cmp.node.discover_workloads")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    workloads = await toolkit.discover_workloads(
        tenant_id,
    )
    data = [w.model_dump() for w in workloads]

    note = f"Discovered {len(workloads)} workloads for migration assessment"

    return {
        "stage": CMPStage.ASSESS_READINESS.value,
        "workloads": data,
        "total_workloads": len(workloads),
        "current_step": "discover_workloads",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="discover_workloads",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Assess Readiness
# ------------------------------------------------------------------


async def assess_readiness(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Assess migration readiness for workloads."""
    logger.info("cmp.node.assess_readiness")
    state = _to_dict(state)

    workloads = [WorkloadProfile(**w) for w in state.get("workloads", [])]
    assessments = await toolkit.assess_readiness(
        workloads,
    )
    data = [a.model_dump() for a in assessments]

    ready = sum(1 for a in assessments if a.readiness_score > 0.7)
    note = f"Assessed {len(assessments)} workloads, {ready} ready for migration"

    try:
        from .prompts import (
            SYSTEM_ASSESS,
            ReadinessInsight,
        )

        ctx = json.dumps(
            {
                "workloads": [
                    {
                        "name": a.workload_name,
                        "strategy": a.strategy.value,
                        "risk": a.risk.value,
                        "score": a.readiness_score,
                    }
                    for a in assessments[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            ReadinessInsight,
            await llm_structured(
                system_prompt=SYSTEM_ASSESS,
                user_prompt=(f"Readiness assessment:\n{ctx}"),
                schema=ReadinessInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cmp",
            node="assess_readiness",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cmp",
            node="assess_readiness",
        )

    return {
        "stage": CMPStage.PLAN_MIGRATION.value,
        "assessments": data,
        "current_step": "assess_readiness",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="assess_readiness",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Plan Migration
# ------------------------------------------------------------------


async def plan_migration(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Create migration plans from assessments."""
    logger.info("cmp.node.plan_migration")
    state = _to_dict(state)

    assessments = [ReadinessAssessment(**a) for a in state.get("assessments", [])]
    plans = await toolkit.plan_migration(assessments)
    data = [p.model_dump() for p in plans]

    total_cost = sum(p.estimated_cost for p in plans)
    total_hours = sum(p.estimated_hours for p in plans)
    note = (
        f"Created {len(plans)} migration plans, "
        f"${total_cost:,.0f} est. cost, "
        f"{total_hours:.0f}h total effort"
    )

    return {
        "stage": CMPStage.VALIDATE_DEPENDENCIES.value,
        "plans": data,
        "total_estimated_cost": round(total_cost, 2),
        "current_step": "plan_migration",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="plan_migration",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Validate Dependencies
# ------------------------------------------------------------------


async def validate_dependencies(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Validate dependencies between plans."""
    logger.info("cmp.node.validate_dependencies")
    state = _to_dict(state)

    plans = [MigrationPlan(**p) for p in state.get("plans", [])]
    dep_maps = await toolkit.validate_dependencies(
        plans,
    )
    data = [d.model_dump() for d in dep_maps]

    circular = sum(1 for d in dep_maps if d.circular)
    note = f"Validated {len(dep_maps)} dependency maps, {circular} circular dependencies"

    return {
        "stage": CMPStage.EXECUTE_MIGRATION.value,
        "dependency_maps": data,
        "current_step": "validate_dependencies",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="validate_dependencies",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Execute Migration
# ------------------------------------------------------------------


async def execute_migration(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Execute migration plans."""
    logger.info("cmp.node.execute_migration")
    state = _to_dict(state)

    plans = [MigrationPlan(**p) for p in state.get("plans", [])]
    executions = await toolkit.execute_migration(
        plans,
    )
    data = [e.model_dump() for e in executions]

    completed = sum(1 for e in executions if e.status == "completed")
    in_progress = sum(1 for e in executions if e.status == "in_progress")
    note = (
        f"Executed {len(executions)} migrations: {completed} completed, {in_progress} in progress"
    )

    return {
        "stage": CMPStage.REPORT.value,
        "executions": data,
        "current_step": "execute_migration",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="execute_migration",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any],
    toolkit: CloudMigrationPlannerToolkit,
) -> dict[str, Any]:
    """Compile the final migration report."""
    logger.info("cmp.node.report")
    state = _to_dict(state)

    total_workloads = state.get("total_workloads", 0)
    total_cost = state.get(
        "total_estimated_cost",
        0.0,
    )
    plan_count = len(state.get("plans", []))
    exec_count = len(state.get("executions", []))
    assess_count = len(state.get("assessments", []))

    lines = [
        "# Cloud Migration Report",
        "",
        f"**Total workloads:** {total_workloads}",
        f"**Assessments:** {assess_count}",
        f"**Migration plans:** {plan_count}",
        f"**Executions:** {exec_count}",
        f"**Estimated cost:** ${total_cost:,.2f}",
    ]

    report_text = "\n".join(lines)

    try:
        from .prompts import (
            SYSTEM_REPORT,
            ReportInsight,
        )

        ctx = json.dumps(
            {
                "total_workloads": total_workloads,
                "total_cost": total_cost,
                "plan_count": plan_count,
                "exec_count": exec_count,
            },
            default=str,
        )
        llm_result = cast(
            ReportInsight,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=(f"Migration report:\n{ctx}"),
                schema=ReportInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="cmp",
            node="report",
        )
        report_text = f"{report_text}\n\n## Summary\n{llm_result.summary}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="cmp",
            node="report",
        )

    return {
        "stage": CMPStage.REPORT.value,
        "report": report_text,
        "current_step": "report",
        "reasoning_chain": state.get(
            "reasoning_chain",
            [],
        )
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
