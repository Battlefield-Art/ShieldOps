"""Policy Engine Agent — Node function implementations."""

from __future__ import annotations

import json
import time
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    GeneratedPolicy,
    PolicyDrift,
    PolicyStage,
    SecurityRequirement,
)
from .tools import PolicyEngineToolkit

logger = structlog.get_logger()

# Module-level toolkit reference for node functions
_toolkit: PolicyEngineToolkit | None = None


def set_toolkit(toolkit: PolicyEngineToolkit) -> None:
    """Set the module-level toolkit for node functions."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> PolicyEngineToolkit:
    """Get the module-level toolkit, creating a default if needed."""
    global _toolkit
    if _toolkit is None:
        _toolkit = PolicyEngineToolkit()
    return _toolkit


def _to_dict(state: Any) -> dict[str, Any]:
    """Convert state to dict, handling both dict and Pydantic model inputs."""
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Collect Requirements
# ------------------------------------------------------------------


async def collect_requirements(
    state: dict[str, Any], toolkit: PolicyEngineToolkit
) -> dict[str, Any]:
    """Collect security requirements from compliance frameworks."""
    logger.info("policy_engine.node.collect_requirements")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    requirements = await toolkit.collect_requirements(tenant_id)
    requirements_data = [r.model_dump() for r in requirements]

    reasoning_note = f"Collected {len(requirements)} security requirements for tenant '{tenant_id}'"

    # LLM enhancement: analyze requirement quality
    try:
        from .prompts import SYSTEM_REQUIREMENTS_ANALYSIS, RequirementsOutput

        context = json.dumps(
            {
                "tenant_id": tenant_id,
                "total_requirements": len(requirements),
                "frameworks": list({r.framework for r in requirements}),
                "requirements_summary": [
                    {
                        "title": r.title,
                        "framework": r.framework,
                        "priority": r.priority,
                    }
                    for r in requirements[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RequirementsOutput,
            await llm_structured(
                system_prompt=SYSTEM_REQUIREMENTS_ANALYSIS,
                user_prompt=(f"Security requirements context:\n{context}"),
                schema=RequirementsOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="policy_engine",
            node="collect_requirements",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="policy_engine",
            node="collect_requirements",
        )

    return {
        "stage": PolicyStage.GENERATE_POLICIES.value,
        "requirements": requirements_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }


# ------------------------------------------------------------------
# Node 2: Generate Policies
# ------------------------------------------------------------------


async def generate_policies(state: dict[str, Any], toolkit: PolicyEngineToolkit) -> dict[str, Any]:
    """Generate OPA Rego policies from collected requirements."""
    logger.info("policy_engine.node.generate_policies")
    state = _to_dict(state)

    raw_reqs = state.get("requirements", [])
    requirements = [SecurityRequirement(**r) for r in raw_reqs]

    policies = await toolkit.generate_rego_policies(requirements)
    policies_data = [p.model_dump() for p in policies]

    reasoning_note = (
        f"Generated {len(policies)} OPA Rego policies covering "
        f"{sum(len(p.requirements_covered) for p in policies)} requirements"
    )

    # LLM enhancement: review generated policies
    try:
        from .prompts import SYSTEM_POLICY_GENERATION, PolicyGenerationOutput

        context = json.dumps(
            {
                "total_policies": len(policies),
                "policy_types": [p.policy_type.value for p in policies],
                "policies_summary": [
                    {
                        "name": p.name,
                        "type": p.policy_type.value,
                        "requirements_covered": len(p.requirements_covered),
                        "rego_lines": len(p.rego_code.strip().splitlines()),
                    }
                    for p in policies
                ],
            },
            default=str,
        )
        llm_result = cast(
            PolicyGenerationOutput,
            await llm_structured(
                system_prompt=SYSTEM_POLICY_GENERATION,
                user_prompt=(f"Policy generation context:\n{context}"),
                schema=PolicyGenerationOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="policy_engine",
            node="generate_policies",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="policy_engine",
            node="generate_policies",
        )

    return {
        "stage": PolicyStage.VALIDATE_COVERAGE.value,
        "generated_policies": policies_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }


# ------------------------------------------------------------------
# Node 3: Validate Coverage
# ------------------------------------------------------------------


async def validate_coverage(state: dict[str, Any], toolkit: PolicyEngineToolkit) -> dict[str, Any]:
    """Validate that all requirements are covered by generated policies."""
    logger.info("policy_engine.node.validate_coverage")
    state = _to_dict(state)

    raw_policies = state.get("generated_policies", [])
    raw_reqs = state.get("requirements", [])
    policies = [GeneratedPolicy(**p) for p in raw_policies]
    requirements = [SecurityRequirement(**r) for r in raw_reqs]

    gaps = await toolkit.validate_coverage(policies, requirements)
    gaps_data = [g.model_dump() for g in gaps]

    reasoning_note = (
        f"Coverage validation: {len(requirements) - len(gaps)}/{len(requirements)} "
        f"requirements covered, {len(gaps)} gaps found"
    )

    # LLM enhancement: deeper coverage analysis
    try:
        from .prompts import SYSTEM_COVERAGE_VALIDATION, CoverageOutput

        context = json.dumps(
            {
                "total_requirements": len(requirements),
                "total_policies": len(policies),
                "coverage_gaps": len(gaps),
                "gaps_summary": [
                    {
                        "requirement": g.requirement_title,
                        "severity": g.severity,
                        "description": g.gap_description,
                    }
                    for g in gaps[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            CoverageOutput,
            await llm_structured(
                system_prompt=SYSTEM_COVERAGE_VALIDATION,
                user_prompt=f"Coverage context:\n{context}",
                schema=CoverageOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="policy_engine",
            node="validate_coverage",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="policy_engine",
            node="validate_coverage",
        )

    return {
        "stage": PolicyStage.DETECT_DRIFT.value,
        "coverage_gaps": gaps_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }


# ------------------------------------------------------------------
# Node 4: Detect Drift
# ------------------------------------------------------------------


async def detect_drift(state: dict[str, Any], toolkit: PolicyEngineToolkit) -> dict[str, Any]:
    """Detect drift between deployed and defined policies."""
    logger.info("policy_engine.node.detect_drift")
    state = _to_dict(state)

    raw_policies = state.get("generated_policies", [])
    policies = [GeneratedPolicy(**p) for p in raw_policies]

    drifts = await toolkit.detect_drift(policies)
    drifts_data = [d.model_dump() for d in drifts]

    reasoning_note = f"Drift detection: found {len(drifts)} drifts across {len(policies)} policies"

    # LLM enhancement: analyze drift root causes
    try:
        from .prompts import SYSTEM_DRIFT_DETECTION, DriftOutput

        context = json.dumps(
            {
                "total_policies": len(policies),
                "total_drifts": len(drifts),
                "drifts_summary": [
                    {
                        "policy": d.policy_name,
                        "type": d.drift_type,
                        "severity": d.severity.value,
                        "auto_reconcilable": d.auto_reconcilable,
                    }
                    for d in drifts[:15]
                ],
            },
            default=str,
        )
        llm_result = cast(
            DriftOutput,
            await llm_structured(
                system_prompt=SYSTEM_DRIFT_DETECTION,
                user_prompt=f"Drift detection context:\n{context}",
                schema=DriftOutput,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="policy_engine",
            node="detect_drift",
        )
        reasoning_note = f"{llm_result.summary} {reasoning_note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="policy_engine",
            node="detect_drift",
        )

    return {
        "stage": PolicyStage.RECONCILE.value,
        "policy_drifts": drifts_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }


# ------------------------------------------------------------------
# Node 5: Reconcile
# ------------------------------------------------------------------


async def reconcile(state: dict[str, Any], toolkit: PolicyEngineToolkit) -> dict[str, Any]:
    """Auto-reconcile driftable policy issues."""
    logger.info("policy_engine.node.reconcile")
    state = _to_dict(state)

    raw_drifts = state.get("policy_drifts", [])
    drifts = [PolicyDrift(**d) for d in raw_drifts]

    actions = await toolkit.reconcile_drift(drifts)
    actions_data = [a.model_dump() for a in actions]

    auto_fixed = sum(1 for a in actions if a.applied and a.success)
    manual_review = sum(1 for a in actions if not a.applied)

    reasoning_note = (
        f"Reconciliation: {auto_fixed} auto-fixed, {manual_review} flagged for manual review"
    )

    return {
        "stage": PolicyStage.REPORT.value,
        "reconciliation_actions": actions_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }


# ------------------------------------------------------------------
# Node 6: Generate Report
# ------------------------------------------------------------------


async def generate_report(state: dict[str, Any], toolkit: PolicyEngineToolkit) -> dict[str, Any]:
    """Generate final policy engine report with stats."""
    logger.info("policy_engine.node.generate_report")
    state = _to_dict(state)

    requirements = state.get("requirements", [])
    policies = state.get("generated_policies", [])
    gaps = state.get("coverage_gaps", [])
    drifts = state.get("policy_drifts", [])
    actions = state.get("reconciliation_actions", [])

    session_start = state.get("session_start", 0.0)
    duration = (time.time() - session_start) * 1000 if session_start else 0.0

    critical_drifts = sum(
        1 for d in drifts if (d.get("severity") if isinstance(d, dict) else d) == "critical"
    )

    stats = {
        "total_requirements": len(requirements),
        "total_policies_generated": len(policies),
        "coverage_gaps": len(gaps),
        "coverage_pct": round(
            ((len(requirements) - len(gaps)) / max(len(requirements), 1)) * 100,
            1,
        ),
        "total_drifts": len(drifts),
        "critical_drifts": critical_drifts,
        "auto_reconciled": sum(
            1 for a in actions if (a.get("applied", False) if isinstance(a, dict) else a)
        ),
        "manual_review_required": sum(
            1 for a in actions if not (a.get("applied", True) if isinstance(a, dict) else True)
        ),
    }

    reasoning_note = (
        f"Report: {stats['coverage_pct']}% coverage, "
        f"{stats['total_drifts']} drifts ({stats['auto_reconciled']} reconciled)"
    )

    return {
        "stage": PolicyStage.REPORT.value,
        "stats": stats,
        "session_duration_ms": duration,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
        "current_step": state.get("current_step", 0) + 1,
    }
