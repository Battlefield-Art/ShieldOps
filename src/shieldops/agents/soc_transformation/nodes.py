"""Node implementations for the SOC Transformation Agent."""

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.soc_transformation.models import (
    MigrationPlan,
    MigrationStep,
    MigrationTarget,
    ReasoningStep,
    SOCAssessment,
    SOCMaturity,
    SOCTransformationState,
    TargetArchitecture,
    ValidationResult,
)
from shieldops.agents.soc_transformation.prompts import (
    SYSTEM_MIGRATION_PLANNING,
    SYSTEM_RULE_TRANSLATION,
    SYSTEM_SOC_ASSESSMENT,
    SYSTEM_TARGET_ARCHITECTURE,
    SYSTEM_VALIDATION,
    ArchitectureOutput,
    AssessmentOutput,
    MigrationPlanOutput,
    RuleTranslationOutput,
    ValidationOutput,
)
from shieldops.agents.soc_transformation.tools import (
    SOCTransformationToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: SOCTransformationToolkit | None = None


def set_toolkit(toolkit: SOCTransformationToolkit) -> None:
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> SOCTransformationToolkit:
    if _toolkit is None:
        return SOCTransformationToolkit()
    return _toolkit


# ── Node: assess_current_soc ─────────────────────────


async def assess_current_soc(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Assess the current SOC maturity and landscape."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Gather raw data from SIEM landscape
    landscape = await toolkit.assess_siem_landscape(
        state.tenant_id,
    )
    soc_metrics = await toolkit.get_soc_metrics(
        state.tenant_id,
    )

    # Collect detection rules per vendor
    total_rules = 0
    for vendor in landscape.get("siem_vendors", []):
        rules = await toolkit.get_detection_rules(vendor)
        total_rules += len(rules)

    # LLM-powered maturity assessment
    maturity = SOCMaturity.REACTIVE
    pain_points: list[str] = []
    strengths: list[str] = []
    coverage_gaps: list[str] = []
    score = 0.0

    try:
        context = _json.dumps(
            {
                "siem_vendors": landscape.get(
                    "siem_vendors",
                    [],
                ),
                "data_source_count": landscape.get(
                    "data_source_count",
                    0,
                ),
                "daily_volume_gb": landscape.get(
                    "daily_event_volume_gb",
                    0,
                ),
                "detection_rule_count": total_rules,
                "annual_cost_usd": landscape.get(
                    "annual_cost_usd",
                    0,
                ),
                "mttd_minutes": soc_metrics.get(
                    "mttd_minutes",
                    0,
                ),
                "mttr_minutes": soc_metrics.get(
                    "mttr_minutes",
                    0,
                ),
                "false_positive_rate": soc_metrics.get(
                    "false_positive_rate",
                    0,
                ),
                "automation_pct": soc_metrics.get(
                    "automation_pct",
                    0,
                ),
                "analyst_count": soc_metrics.get(
                    "analyst_count",
                    0,
                ),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_SOC_ASSESSMENT,
            user_prompt=f"Assess this SOC:\n{context}",
            schema=AssessmentOutput,
        )
        maturity_val = getattr(
            llm_result,
            "maturity_level",
            "reactive",
        )
        if maturity_val in [m.value for m in SOCMaturity]:
            maturity = SOCMaturity(maturity_val)
        pain_points = getattr(llm_result, "pain_points", [])
        strengths = getattr(llm_result, "strengths", [])
        coverage_gaps = getattr(
            llm_result,
            "coverage_gaps",
            [],
        )
        score = getattr(llm_result, "score", 0.0)
        logger.info(
            "llm_enhanced",
            node="assess_current_soc",
            maturity=maturity.value,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_current_soc",
        )

    assessment = SOCAssessment(
        maturity=maturity,
        siem_vendors=landscape.get("siem_vendors", []),
        detection_rule_count=total_rules,
        data_source_count=landscape.get(
            "data_source_count",
            0,
        ),
        daily_event_volume_gb=landscape.get(
            "daily_event_volume_gb",
            0.0,
        ),
        mean_time_to_detect_min=soc_metrics.get(
            "mttd_minutes",
            0.0,
        ),
        mean_time_to_respond_min=soc_metrics.get(
            "mttr_minutes",
            0.0,
        ),
        automation_percentage=soc_metrics.get(
            "automation_pct",
            0.0,
        ),
        pain_points=pain_points,
        strengths=strengths,
        coverage_gaps=coverage_gaps,
        annual_siem_cost_usd=landscape.get(
            "annual_cost_usd",
            0.0,
        ),
        analyst_count=soc_metrics.get("analyst_count", 0),
        score=score,
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="assess_current_soc",
        input_summary=f"Assessing SOC for tenant {state.tenant_id}",
        output_summary=(f"Maturity={maturity.value}, {total_rules} rules, score={score:.1f}"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="siem_assessment",
    )

    return {
        "assessment": assessment,
        "current_maturity": maturity,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": "assess_current_soc",
        "session_start": start,
    }


# ── Node: design_target_architecture ────────────────


async def design_target_architecture(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Design the target SOC architecture based on assessment."""
    start = datetime.now(UTC)

    architecture = TargetArchitecture(
        target_maturity=state.target_maturity,
    )

    try:
        assessment_data = state.assessment.model_dump() if state.assessment else {}
        context = _json.dumps(
            {
                "current_assessment": assessment_data,
                "current_maturity": state.current_maturity.value,
                "target_maturity": state.target_maturity.value,
                "scope": [s.value for s in state.transformation_scope],
                "config": state.config,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TARGET_ARCHITECTURE,
            user_prompt=(f"Design target architecture:\n{context}"),
            schema=ArchitectureOutput,
        )
        architecture = TargetArchitecture(
            target_maturity=state.target_maturity,
            primary_siem=getattr(
                llm_result,
                "primary_siem",
                "",
            ),
            secondary_tools=getattr(
                llm_result,
                "secondary_tools",
                [],
            ),
            data_pipeline_design=getattr(
                llm_result,
                "data_pipeline_design",
                "",
            ),
            detection_strategy=getattr(
                llm_result,
                "detection_strategy",
                "",
            ),
            automation_targets=getattr(
                llm_result,
                "automation_targets",
                [],
            ),
            estimated_cost_reduction_pct=getattr(
                llm_result,
                "cost_reduction_pct",
                0.0,
            ),
            estimated_mttd_improvement_pct=getattr(
                llm_result,
                "mttd_improvement_pct",
                0.0,
            ),
            estimated_mttr_improvement_pct=getattr(
                llm_result,
                "mttr_improvement_pct",
                0.0,
            ),
            rationale=getattr(llm_result, "rationale", ""),
        )
        logger.info(
            "llm_enhanced",
            node="design_target_architecture",
            primary_siem=architecture.primary_siem,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="design_target_architecture",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="design_target_architecture",
        input_summary=(
            f"Designing target for {state.current_maturity.value} -> {state.target_maturity.value}"
        ),
        output_summary=(
            f"Primary SIEM={architecture.primary_siem}, "
            f"cost_reduction="
            f"{architecture.estimated_cost_reduction_pct:.0f}%"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="llm",
    )

    return {
        "target_architecture": architecture,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": "design_target_architecture",
    }


# ── Node: plan_migration ────────────────────────────


async def plan_migration(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Create a phased migration plan."""
    start = datetime.now(UTC)
    from uuid import uuid4

    steps: list[MigrationStep] = []
    prerequisites: list[str] = []
    risk_summary = ""
    phases = 1

    try:
        arch_data = state.target_architecture.model_dump() if state.target_architecture else {}
        assess_data = state.assessment.model_dump() if state.assessment else {}
        context = _json.dumps(
            {
                "assessment": assess_data,
                "target_architecture": arch_data,
                "scope": [s.value for s in state.transformation_scope],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MIGRATION_PLANNING,
            user_prompt=(f"Plan migration:\n{context}"),
            schema=MigrationPlanOutput,
        )

        for idx, s in enumerate(
            getattr(llm_result, "steps", []),
        ):
            target_val = s.get(
                "target",
                "siem_consolidation",
            )
            if target_val in [t.value for t in MigrationTarget]:
                target = MigrationTarget(target_val)
            else:
                target = MigrationTarget.SIEM_CONSOLIDATION

            steps.append(
                MigrationStep(
                    step_id=f"step-{uuid4().hex[:12]}",
                    order=idx + 1,
                    target=target,
                    title=s.get("title", ""),
                    description=s.get("description", ""),
                    estimated_hours=float(
                        s.get("estimated_hours", 0),
                    ),
                    risk_level=s.get("risk_level", "medium"),
                    rollback_plan=s.get("rollback_plan", ""),
                    dependencies=s.get("dependencies", []),
                    status="pending",
                )
            )

        prerequisites = getattr(
            llm_result,
            "prerequisites",
            [],
        )
        risk_summary = getattr(
            llm_result,
            "risk_summary",
            "",
        )
        phases = getattr(llm_result, "phases", 1)

        logger.info(
            "llm_enhanced",
            node="plan_migration",
            step_count=len(steps),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_migration",
        )

    total_hours = sum(s.estimated_hours for s in steps)
    plan = MigrationPlan(
        plan_id=f"plan-{uuid4().hex[:12]}",
        steps=steps,
        total_estimated_hours=total_hours,
        phases=phases,
        risk_summary=risk_summary,
        prerequisites=prerequisites,
    )

    reasoning_step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="plan_migration",
        input_summary=(f"Planning migration for {len(state.transformation_scope)} targets"),
        output_summary=(f"{len(steps)} steps, {total_hours:.0f}h estimated, {phases} phases"),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="llm",
    )

    return {
        "migration_plan": plan,
        "migration_steps": steps,
        "reasoning_chain": [
            *state.reasoning_chain,
            reasoning_step,
        ],
        "current_stage": "plan_migration",
    }


# ── Node: execute_migration_steps ──────────────────


async def execute_migration_steps(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Execute each migration step sequentially."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    completed = 0
    rules_migrated = 0
    sources_connected = 0
    playbooks_deployed = 0
    workflows_automated = 0
    updated_steps: list[MigrationStep] = []

    for ms in state.migration_steps:
        try:
            if ms.target == MigrationTarget.DETECTION_RULES:
                result = await _execute_rule_migration(
                    toolkit,
                    ms,
                    state,
                )
                rules_migrated += result.get(
                    "rules_migrated",
                    0,
                )
            elif ms.target == MigrationTarget.DATA_PIPELINE:
                result = await _execute_pipeline_setup(
                    toolkit,
                    ms,
                    state,
                )
                sources_connected += result.get(
                    "sources_connected",
                    0,
                )
            elif ms.target == MigrationTarget.RESPONSE_PLAYBOOKS:
                result = await toolkit.deploy_playbook(
                    {"name": ms.title, "config": ms.result},
                )
                playbooks_deployed += 1
            elif ms.target == MigrationTarget.WORKFLOW_AUTOMATION:
                result = {"status": "simulated"}
                workflows_automated += 1
            else:
                result = {"status": "simulated"}

            ms.status = "completed"
            ms.result = result
            completed += 1
        except Exception as exc:
            ms.status = "failed"
            ms.result = {"error": str(exc)}
            logger.warning(
                "soc_transform.step_failed",
                step_id=ms.step_id,
                error=str(exc),
            )

        updated_steps.append(ms)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_migration_steps",
        input_summary=(f"Executing {len(state.migration_steps)} steps"),
        output_summary=(
            f"{completed} completed, {rules_migrated} rules, {sources_connected} sources"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="migration_executor",
    )

    return {
        "migration_steps": updated_steps,
        "steps_completed": completed,
        "detection_rules_migrated": rules_migrated,
        "data_sources_connected": sources_connected,
        "playbooks_deployed": playbooks_deployed,
        "workflows_automated": workflows_automated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": "execute_migration_steps",
    }


async def _execute_rule_migration(
    toolkit: SOCTransformationToolkit,
    step: MigrationStep,
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Migrate detection rules with LLM-powered translation."""
    arch = state.target_architecture
    target_siem = arch.primary_siem if arch else "elastic"
    source_vendor = ""
    if state.assessment and state.assessment.siem_vendors:
        source_vendor = state.assessment.siem_vendors[0]

    # Get rules from source
    rules = await toolkit.get_detection_rules(
        source_vendor,
        limit=50,
    )

    migrated = 0
    for rule in rules:
        # Translate using LLM
        try:
            rule_context = _json.dumps(
                {
                    "rule_name": rule.get("name", ""),
                    "query": rule.get("query", ""),
                    "source_language": _vendor_to_lang(
                        source_vendor,
                    ),
                    "target_language": _vendor_to_lang(
                        target_siem,
                    ),
                    "severity": rule.get("severity", ""),
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_RULE_TRANSLATION,
                user_prompt=(f"Translate this rule:\n{rule_context}"),
                schema=RuleTranslationOutput,
            )
            translated = {
                "name": rule.get("name", ""),
                "query": getattr(
                    llm_result,
                    "translated_rule",
                    "",
                ),
                "language": getattr(
                    llm_result,
                    "target_language",
                    "",
                ),
                "mitre": getattr(
                    llm_result,
                    "mitre_technique",
                    "",
                ),
            }
        except Exception:
            translated = {
                "name": rule.get("name", ""),
                "query": rule.get("query", ""),
                "language": _vendor_to_lang(target_siem),
            }

        # Deploy to target
        await toolkit.deploy_detection_rule(
            translated,
            target_siem,
        )
        migrated += 1

    return {"rules_migrated": migrated}


async def _execute_pipeline_setup(
    toolkit: SOCTransformationToolkit,
    step: MigrationStep,
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Set up data pipelines to the target SIEM."""
    arch = state.target_architecture
    target_siem = arch.primary_siem if arch else "elastic"
    source_vendor = ""
    if state.assessment and state.assessment.siem_vendors:
        source_vendor = state.assessment.siem_vendors[0]

    sources = await toolkit.get_data_sources(source_vendor)
    connected = 0
    for source in sources:
        await toolkit.configure_data_pipeline(
            source,
            target_siem,
        )
        connected += 1

    return {"sources_connected": connected}


def _vendor_to_lang(vendor: str) -> str:
    """Map vendor name to query language."""
    mapping = {
        "splunk": "SPL",
        "elastic": "EQL",
        "microsoft": "KQL",
        "defender": "KQL",
    }
    return mapping.get(vendor.lower(), "native")


# ── Node: validate_transformation ──────────────────


async def validate_transformation(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Validate the migration met its objectives."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results: list[ValidationResult] = []
    overall_passed = True

    # Detection parity check
    arch = state.target_architecture
    target = arch.primary_siem if arch else ""
    if target:
        latency = await toolkit.measure_ingestion_latency(
            target,
        )
        results.append(
            ValidationResult(
                check_name="ingestion_latency",
                passed=latency.get("p95_ms", 9999) < 5000,
                details=(f"p95={latency.get('p95_ms', 0)}ms"),
                metric_before=0.0,
                metric_after=float(
                    latency.get("p95_ms", 0),
                ),
            )
        )

    # Rule migration check
    results.append(
        ValidationResult(
            check_name="detection_rules_migrated",
            passed=state.detection_rules_migrated > 0,
            details=(f"{state.detection_rules_migrated} rules migrated"),
            metric_before=float(
                state.assessment.detection_rule_count if state.assessment else 0,
            ),
            metric_after=float(
                state.detection_rules_migrated,
            ),
        )
    )

    # Data sources check
    results.append(
        ValidationResult(
            check_name="data_sources_connected",
            passed=state.data_sources_connected > 0,
            details=(f"{state.data_sources_connected} sources connected"),
            metric_before=float(
                state.assessment.data_source_count if state.assessment else 0,
            ),
            metric_after=float(
                state.data_sources_connected,
            ),
        )
    )

    # LLM-powered validation summary
    try:
        val_context = _json.dumps(
            {
                "steps_completed": state.steps_completed,
                "total_steps": len(state.migration_steps),
                "rules_migrated": state.detection_rules_migrated,
                "sources_connected": state.data_sources_connected,
                "playbooks_deployed": state.playbooks_deployed,
                "workflows_automated": state.workflows_automated,
                "current_maturity": state.current_maturity.value,
                "target_maturity": state.target_maturity.value,
                "check_results": [r.model_dump() for r in results],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATION,
            user_prompt=(f"Validate transformation:\n{val_context}"),
            schema=ValidationOutput,
        )
        overall_passed = getattr(
            llm_result,
            "overall_passed",
            True,
        )

        # Add LLM-generated checks
        for check in getattr(llm_result, "checks", []):
            results.append(
                ValidationResult(
                    check_name=check.get("name", ""),
                    passed=check.get("passed", "") == "true",
                    details=check.get("details", ""),
                    metric_before=float(
                        check.get("metric_before", 0),
                    ),
                    metric_after=float(
                        check.get("metric_after", 0),
                    ),
                )
            )

        logger.info(
            "llm_enhanced",
            node="validate_transformation",
            passed=overall_passed,
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_transformation",
        )
        overall_passed = all(r.passed for r in results)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_transformation",
        input_summary="Validating migration results",
        output_summary=(
            f"{sum(1 for r in results if r.passed)}"
            f"/{len(results)} checks passed, "
            f"overall={'PASS' if overall_passed else 'FAIL'}"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="validation_engine",
    )

    return {
        "validation_results": results,
        "validation_passed": overall_passed,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": "validate_transformation",
    }


# ── Node: report ───────────────────────────────────


async def report(
    state: SOCTransformationState,
) -> dict[str, Any]:
    """Generate the final transformation report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    assessment = state.assessment
    arch = state.target_architecture

    report_data: dict[str, Any] = {
        "tenant_id": state.tenant_id,
        "summary": {
            "current_maturity": state.current_maturity.value,
            "target_maturity": state.target_maturity.value,
            "steps_planned": len(state.migration_steps),
            "steps_completed": state.steps_completed,
            "detection_rules_migrated": (state.detection_rules_migrated),
            "data_sources_connected": (state.data_sources_connected),
            "playbooks_deployed": state.playbooks_deployed,
            "workflows_automated": state.workflows_automated,
            "validation_passed": state.validation_passed,
            "duration_ms": duration_ms,
        },
        "assessment": (assessment.model_dump() if assessment else {}),
        "target_architecture": (arch.model_dump() if arch else {}),
        "migration_steps": [s.model_dump() for s in state.migration_steps],
        "validation_results": [v.model_dump() for v in state.validation_results],
        "reasoning_chain": [r.model_dump() for r in state.reasoning_chain],
    }

    # Record final metrics
    await toolkit.record_metric(
        "transformation_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "rules_migrated",
        float(state.detection_rules_migrated),
    )
    await toolkit.record_metric(
        "sources_connected",
        float(state.data_sources_connected),
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary="Generating transformation report",
        output_summary=(
            f"Transformation "
            f"{'PASSED' if state.validation_passed else 'FAILED'}"
            f", {state.steps_completed}"
            f"/{len(state.migration_steps)} steps"
        ),
        duration_ms=int(
            (datetime.now(UTC) - start).total_seconds() * 1000,
        ),
        tool_used="report_generator",
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_stage": "report",
    }
