"""Node implementations for the AI Blue Team Agent LangGraph workflow."""

from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

import structlog

from shieldops.agents.ai_blue_team.models import (
    AIBlueTeamState,
    DetectionRule,
    HardeningAction,
    ReasoningStep,
    SecurityGap,
)
from shieldops.agents.ai_blue_team.prompts import (
    SYSTEM_DETECTION_RULES,
    SYSTEM_GAP_ANALYSIS,
    SYSTEM_HARDENING_PLAN,
    DetectionRuleOutput,
    GapAnalysisOutput,
    HardeningPlanOutput,
)
from shieldops.agents.ai_blue_team.tools import AIBlueTeamToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AIBlueTeamToolkit | None = None


def _get_toolkit() -> AIBlueTeamToolkit:
    if _toolkit is None:
        return AIBlueTeamToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


async def analyze_findings(state: AIBlueTeamState) -> dict[str, Any]:
    """Analyze red team findings to understand attack patterns."""
    start = datetime.now(UTC)

    logger.info(
        "ai_blue_team.analyzing_findings",
        finding_count=len(state.red_team_findings),
    )

    context_lines = [
        "## Red Team Findings",
        *[f"- {f}" for f in state.red_team_findings[:20]],
        "",
        "## Environment Context",
        *[f"- {k}: {v}" for k, v in state.environment_context.items()],
    ]
    user_prompt = "\n".join(context_lines)

    gaps: list[SecurityGap] = []
    try:
        result = cast(
            GapAnalysisOutput,
            await llm_structured(
                system_prompt=SYSTEM_GAP_ANALYSIS,
                user_prompt=user_prompt,
                schema=GapAnalysisOutput,
            ),
        )
        for g in result.gaps:
            gaps.append(
                SecurityGap(
                    gap_id=f"gap-{uuid4().hex[:8]}",
                    category=g.get("category", ""),
                    description=g.get("description", ""),
                    severity=g.get("severity", "medium"),
                    affected_assets=g.get("affected_assets", []),
                    red_team_technique=g.get("technique", ""),
                    current_control=g.get("current_control", ""),
                    recommended_control=g.get("recommended_control", ""),
                )
            )
        output_summary = f"{result.summary[:150]}. Most critical: {result.most_critical_gap[:80]}"
    except Exception as e:
        logger.error("ai_blue_team.gap_analysis_failed", error=str(e))
        output_summary = f"Gap analysis failed: {e}"
        # Fallback: create generic gaps from findings
        for i, finding in enumerate(state.red_team_findings[:5]):
            gaps.append(
                SecurityGap(
                    gap_id=f"gap-{uuid4().hex[:8]}",
                    category="monitoring",
                    description=str(finding),
                    severity="high" if i == 0 else "medium",
                )
            )

    step = ReasoningStep(
        step_number=1,
        action="analyze_findings",
        input_summary=f"Analyzing {len(state.red_team_findings)} red team findings",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "gaps_identified": gaps,
        "reasoning_chain": [step],
        "current_step": "analyze_findings",
        "session_start": start,
    }


async def identify_gaps(state: AIBlueTeamState) -> dict[str, Any]:
    """Further analyze and prioritize identified security gaps."""
    start = datetime.now(UTC)

    # Sort gaps by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_gaps = sorted(
        state.gaps_identified,
        key=lambda g: severity_order.get(g.severity, 4),
    )

    critical_count = sum(1 for g in sorted_gaps if g.severity in ("critical", "high"))

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="identify_gaps",
        input_summary=f"Prioritizing {len(state.gaps_identified)} gaps",
        output_summary=f"Prioritized: {critical_count} critical/high, {len(sorted_gaps)} total",
        duration_ms=_elapsed_ms(start),
    )

    return {
        "gaps_identified": sorted_gaps,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "identify_gaps",
    }


async def generate_hardening_plan(state: AIBlueTeamState) -> dict[str, Any]:
    """Generate hardening actions using LLM analysis of gaps."""
    start = datetime.now(UTC)

    logger.info("ai_blue_team.generating_hardening_plan", gap_count=len(state.gaps_identified))

    context_lines = ["## Security Gaps"]
    for gap in state.gaps_identified[:15]:
        context_lines.append(
            f"- [{gap.severity}] {gap.category}: {gap.description}. "
            f"Affected: {gap.affected_assets}. Current: {gap.current_control}"
        )
    context_lines.append(f"\n## Scope: {state.hardening_scope}")

    user_prompt = "\n".join(context_lines)

    actions: list[HardeningAction] = []
    try:
        result = cast(
            HardeningPlanOutput,
            await llm_structured(
                system_prompt=SYSTEM_HARDENING_PLAN,
                user_prompt=user_prompt,
                schema=HardeningPlanOutput,
            ),
        )
        for a in result.actions:
            actions.append(
                HardeningAction(
                    action_id=f"harden-{uuid4().hex[:8]}",
                    action_type=a.get("type", "config_change"),
                    target_asset=a.get("target", ""),
                    description=a.get("description", ""),
                    priority=a.get("priority", "standard"),
                    risk_reduction_pct=a.get("risk_reduction_pct", 0.0),
                    rollback_plan=a.get("rollback_plan", ""),
                    estimated_time_minutes=a.get("time_minutes", 30),
                )
            )
        output_summary = (
            f"{result.summary[:150]}. "
            f"Est. risk reduction: {result.estimated_total_risk_reduction_pct}%"
        )
    except Exception as e:
        logger.error("ai_blue_team.hardening_plan_failed", error=str(e))
        output_summary = f"Hardening plan generation failed: {e}"
        for gap in state.gaps_identified[:5]:
            actions.append(
                HardeningAction(
                    action_id=f"harden-{uuid4().hex[:8]}",
                    action_type="config_change",
                    target_asset=", ".join(gap.affected_assets[:3]),
                    description=f"Harden: {gap.description[:80]}",
                    priority="high" if gap.severity in ("critical", "high") else "standard",
                )
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_hardening_plan",
        input_summary=f"Generating hardening plan for {len(state.gaps_identified)} gaps",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm",
    )

    return {
        "hardening_actions": actions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_hardening_plan",
    }


async def apply_hardening(state: AIBlueTeamState) -> dict[str, Any]:
    """Apply hardening actions using the toolkit."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ai_blue_team.applying_hardening",
        action_count=len(state.hardening_actions),
    )

    policies_updated: list[dict[str, Any]] = []
    for action in state.hardening_actions[:10]:
        if action.action_type in ("policy_update", "config_change"):
            result = await toolkit.update_access_policy(
                action.target_asset,
                {"description": action.description, "action_id": action.action_id},
            )
            policies_updated.append(result)
        elif action.action_type == "network_policy":
            result = await toolkit.apply_network_policy(
                action.target_asset,
                {"description": action.description},
            )
            policies_updated.append(result)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="apply_hardening",
        input_summary=f"Applying {len(state.hardening_actions)} hardening actions",
        output_summary=f"Applied {len(policies_updated)} policy updates",
        duration_ms=_elapsed_ms(start),
        tool_used="blue_team_toolkit",
    )

    return {
        "policies_updated": policies_updated,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "apply_hardening",
    }


async def create_detection_rules(state: AIBlueTeamState) -> dict[str, Any]:
    """Create new detection rules to catch red team techniques."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info("ai_blue_team.creating_detection_rules", gap_count=len(state.gaps_identified))

    context_lines = ["## Security Gaps Needing Detection"]
    for gap in state.gaps_identified[:10]:
        context_lines.append(
            f"- [{gap.severity}] {gap.description}. Technique: {gap.red_team_technique}"
        )

    user_prompt = "\n".join(context_lines)

    rules: list[DetectionRule] = []
    try:
        result = cast(
            DetectionRuleOutput,
            await llm_structured(
                system_prompt=SYSTEM_DETECTION_RULES,
                user_prompt=user_prompt,
                schema=DetectionRuleOutput,
            ),
        )
        for r in result.rules:
            rule = DetectionRule(
                rule_id=f"rule-{uuid4().hex[:8]}",
                rule_name=r.get("name", ""),
                mitre_technique_id=r.get("mitre_technique", ""),
                data_source=r.get("data_source", "siem"),
                query=r.get("query", ""),
                severity=r.get("severity", "medium"),
                description=r.get("description", ""),
            )
            rules.append(rule)
            # Deploy the rule
            await toolkit.deploy_detection_rule(
                rule_name=rule.rule_name,
                query=rule.query,
                data_source=rule.data_source,
                severity=rule.severity,
            )
        output_summary = (
            f"{result.summary[:150]}. Coverage improvement: {result.coverage_improvement_pct}%"
        )
    except Exception as e:
        logger.error("ai_blue_team.detection_rules_failed", error=str(e))
        output_summary = f"Detection rule creation failed: {e}"

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="create_detection_rules",
        input_summary=f"Creating detection rules for {len(state.gaps_identified)} gaps",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="llm + detection_deployer",
    )

    return {
        "detection_rules_created": rules,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "create_detection_rules",
    }


async def validate(state: AIBlueTeamState) -> dict[str, Any]:
    """Validate hardening actions and detection rules."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "ai_blue_team.validating",
        actions=len(state.hardening_actions),
        rules=len(state.detection_rules_created),
    )

    validations: list[dict[str, Any]] = []
    regressions: list[dict[str, Any]] = []

    # Validate each hardening action
    for action in state.hardening_actions[:10]:
        result = await toolkit.run_validation_test(
            test_name=f"validate_{action.action_id}",
            target=action.target_asset,
        )
        validations.append(result)

    # Run regression tests
    unique_services = {a.target_asset for a in state.hardening_actions if a.target_asset}
    for service in list(unique_services)[:5]:
        result = await toolkit.run_regression_test(service)
        regressions.append(result)

    all_passed = all(v.get("passed", False) for v in validations)
    regression_passed = all(r.get("passed", False) for r in regressions)

    session_duration = 0
    if state.session_start:
        session_duration = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate",
        input_summary=(
            f"Validating {len(state.hardening_actions)} actions, "
            f"{len(state.detection_rules_created)} rules"
        ),
        output_summary=(
            f"Validations: {'all passed' if all_passed else 'some failed'}. "
            f"Regressions: {'all passed' if regression_passed else 'some failed'}"
        ),
        duration_ms=_elapsed_ms(start),
        tool_used="validation_toolkit",
    )

    return {
        "validation_results": validations,
        "regression_tests": regressions,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
        "session_duration_ms": session_duration,
    }
