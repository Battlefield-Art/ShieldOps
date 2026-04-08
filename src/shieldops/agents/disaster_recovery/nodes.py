"""Node implementations for the Disaster Recovery Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.disaster_recovery.models import (
    DisasterRecoveryState,
    DRGap,
    DRPlan,
    DRStatus,
    FailoverTest,
    ReasoningStep,
)
from shieldops.agents.disaster_recovery.prompts import (
    SYSTEM_ASSESS,
    SYSTEM_GAP_ANALYSIS,
    SYSTEM_REMEDIATION,
    DRAssessmentOutput,
    GapAnalysisOutput,
    RemediationOutput,
)
from shieldops.agents.disaster_recovery.tools import DisasterRecoveryToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DisasterRecoveryToolkit | None = None


def _get_toolkit() -> DisasterRecoveryToolkit:
    if _toolkit is None:
        return DisasterRecoveryToolkit()
    return _toolkit


async def assess_plans(state: DisasterRecoveryState) -> dict[str, Any]:
    """Assess all DR plans for the tenant and evaluate coverage."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_plans = await toolkit.assess_dr_plans(state.tenant_id)
    plans = [DRPlan(**p) for p in raw_plans if isinstance(p, dict)]

    tested_count = sum(1 for p in plans if p.status == DRStatus.TESTED)
    total_services = sum(len(p.services_covered) for p in plans)
    coverage_score = (tested_count / max(len(plans), 1)) * 100

    assessment_summary: dict[str, Any] = {
        "total_plans": len(plans),
        "tested_plans": tested_count,
        "total_services_covered": total_services,
        "coverage_score": coverage_score,
    }

    # LLM enhancement: deeper assessment reasoning
    try:
        import json as _json

        assess_context = _json.dumps(
            {
                "tenant_id": state.tenant_id,
                "plans": [p.model_dump() for p in plans],
                "coverage_score": coverage_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS,
            user_prompt=f"DR plan assessment context:\n{assess_context}",
            schema=DRAssessmentOutput,
        )
        assessment_summary["llm_coverage_score"] = llm_result.coverage_score
        assessment_summary["highest_risk_service"] = llm_result.highest_risk_service
        assessment_summary["recommendation"] = llm_result.recommendation
        logger.info(
            "llm_enhanced",
            node="assess_plans",
            coverage_score=llm_result.coverage_score,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="assess_plans")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_plans",
        input_summary=f"Tenant {state.tenant_id}, {len(raw_plans)} plans discovered",
        output_summary=f"Coverage={coverage_score:.0f}%, {tested_count}/{len(plans)} tested",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="dr_assessment_engine",
    )

    await toolkit.record_dr_metric("coverage_score", coverage_score)

    return {
        "plans": plans,
        "assessment_summary": assessment_summary,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_plans",
        "session_start": start,
    }


async def test_failover(state: DisasterRecoveryState) -> dict[str, Any]:
    """Execute failover tests against each DR plan."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tests: list[FailoverTest] = []
    for plan in state.plans:
        raw_result = await toolkit.execute_failover_test(plan.id, plan.failover_type.value)
        tests.append(FailoverTest(**raw_result))

    success_count = sum(1 for t in tests if t.success)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="test_failover",
        input_summary=f"Testing failover for {len(state.plans)} plans",
        output_summary=f"{success_count}/{len(tests)} tests passed",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="failover_orchestrator",
    )

    await toolkit.record_dr_metric("failover_success_rate", success_count / max(len(tests), 1))

    return {
        "failover_tests": tests,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "test_failover",
    }


async def measure_rto_rpo(state: DisasterRecoveryState) -> dict[str, Any]:
    """Measure RTO/RPO compliance from failover test results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plan_dicts = [p.model_dump() for p in state.plans]
    test_dicts = [t.model_dump() for t in state.failover_tests]
    results = await toolkit.measure_rto_rpo(test_dicts, plan_dicts)

    rto_met = results.get("rto_met", False)
    rpo_met = results.get("rpo_met", False)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="measure_rto_rpo",
        input_summary=f"Measuring RTO/RPO for {len(state.failover_tests)} tests",
        output_summary=f"RTO met={rto_met}, RPO met={rpo_met}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="rto_rpo_analyzer",
    )

    return {
        "rto_rpo_results": results,
        "rto_met": rto_met,
        "rpo_met": rpo_met,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "measure_rto_rpo",
    }


async def identify_gaps(state: DisasterRecoveryState) -> dict[str, Any]:
    """Identify gaps in DR coverage, testing, and compliance."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plan_dicts = [p.model_dump() for p in state.plans]
    test_dicts = [t.model_dump() for t in state.failover_tests]
    raw_gaps = await toolkit.identify_gaps(plan_dicts, test_dicts, state.rto_rpo_results)
    gaps = [DRGap(**g) for g in raw_gaps if isinstance(g, dict)]

    has_critical = any(g.severity == "critical" for g in gaps)

    # LLM enhancement: deeper gap analysis
    try:
        import json as _json

        gap_context = _json.dumps(
            {
                "plans": plan_dicts,
                "failover_tests": test_dicts,
                "rto_rpo_results": state.rto_rpo_results,
                "gaps_found": [g.model_dump() for g in gaps],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_GAP_ANALYSIS,
            user_prompt=f"DR gap analysis context:\n{gap_context}",
            schema=GapAnalysisOutput,
        )
        logger.info(
            "llm_enhanced",
            node="identify_gaps",
            critical_gaps=llm_result.critical_gap_count,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="identify_gaps")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_gaps",
        input_summary=f"Analyzing {len(state.plans)} plans, {len(state.failover_tests)} tests",
        output_summary=f"Found {len(gaps)} gaps, critical={has_critical}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="gap_analyzer",
    )

    return {
        "gaps": gaps,
        "has_critical_gaps": has_critical,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_gaps",
    }


async def remediate(state: DisasterRecoveryState) -> dict[str, Any]:
    """Plan and initiate remediation for identified DR gaps."""
    start = datetime.now(UTC)

    actions: list[dict[str, Any]] = []
    for gap in state.gaps:
        actions.append(
            {
                "gap_id": gap.id,
                "plan_id": gap.plan_id,
                "gap_type": gap.gap_type,
                "action": gap.remediation,
                "severity": gap.severity,
                "status": "planned",
            }
        )

    # LLM enhancement: smarter remediation planning
    try:
        import json as _json

        remediation_context = _json.dumps(
            {"gaps": [g.model_dump() for g in state.gaps]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REMEDIATION,
            user_prompt=f"DR remediation context:\n{remediation_context}",
            schema=RemediationOutput,
        )
        if llm_result.actions:
            for i, llm_action in enumerate(llm_result.actions):
                if i < len(actions):
                    actions[i]["llm_action"] = llm_action.get("action", "")
                    actions[i]["effort"] = llm_action.get("effort", "unknown")
        logger.info(
            "llm_enhanced",
            node="remediate",
            estimated_days=llm_result.estimated_days,
        )
    except Exception:
        logger.debug("llm_enhancement_skipped", node="remediate")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="remediate",
        input_summary=f"Remediating {len(state.gaps)} gaps",
        output_summary=f"Planned {len(actions)} remediation actions",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="remediation_planner",
    )

    return {
        "remediation_actions": actions,
        "remediation_complete": True,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "remediate",
    }


async def report(state: DisasterRecoveryState) -> dict[str, Any]:
    """Generate the final DR assessment report and record metrics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    dr_report: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "plans_assessed": len(state.plans),
        "failover_tests_run": len(state.failover_tests),
        "failover_success_rate": (
            sum(1 for t in state.failover_tests if t.success) / max(len(state.failover_tests), 1)
        ),
        "rto_met": state.rto_met,
        "rpo_met": state.rpo_met,
        "gaps_found": len(state.gaps),
        "critical_gaps": sum(1 for g in state.gaps if g.severity == "critical"),
        "remediation_actions": len(state.remediation_actions),
        "assessment_summary": state.assessment_summary,
        "rto_rpo_results": state.rto_rpo_results,
        "duration_ms": duration_ms,
    }

    await toolkit.record_dr_metric("report_duration_ms", float(duration_ms))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=f"Generating report for tenant {state.tenant_id}",
        output_summary=(
            f"Report complete: {len(state.plans)} plans, "
            f"{len(state.gaps)} gaps, duration={duration_ms}ms"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used=None,
    )

    return {
        "report": dr_report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
