"""Node implementations for the Security Automation Hub LangGraph workflow.

Each node is an async function that:
1. Queries automation systems via the toolkit
2. Uses the LLM to analyze and reason about data
3. Updates the SAH state with findings
4. Records its reasoning step in the audit trail
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import structlog

from shieldops.agents.security_automation_hub.models import (
    AutomationExecution,
    AutomationStatus,
    ReasoningStep,
    SAHStage,
    SecurityAutomationHubState,
    SecurityTrigger,
    ValidationResult,
)
from shieldops.agents.security_automation_hub.prompts import (
    SYSTEM_EXECUTE_AUTOMATIONS,
    SYSTEM_INGEST_TRIGGERS,
    SYSTEM_LEARN_OUTCOMES,
    SYSTEM_MATCH_PLAYBOOKS,
    SYSTEM_VALIDATE_RESULTS,
    ExecutionAnalysis,
    LearningAnalysis,
    PlaybookAnalysis,
    TriggerAnalysis,
    ValidationAnalysis,
)
from shieldops.agents.security_automation_hub.tools import (
    SecurityAutomationHubToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

# Module-level toolkit, set by runner at startup.
_toolkit: SecurityAutomationHubToolkit | None = None


def _get_toolkit() -> SecurityAutomationHubToolkit:
    if _toolkit is None:
        return SecurityAutomationHubToolkit()
    return _toolkit


def _elapsed_ms(start: datetime) -> int:
    return int((datetime.now(UTC) - start).total_seconds() * 1000)


# ---- Node: ingest_triggers ----


async def ingest_triggers(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Ingest security triggers from configured sources."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    logger.info(
        "sah_ingesting_triggers",
        request_id=state.request_id,
    )

    sources = state.config.get("sources")
    triggers = await toolkit.ingest_triggers(
        tenant_id=state.tenant_id,
        sources=sources,
    )

    output_summary = f"Ingested {len(triggers)} security triggers."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "triggers_ingested": len(triggers),
                "types": list({t.trigger_type.value for t in triggers}),
                "severities": [t.severity for t in triggers],
                "sources": list({t.source for t in triggers}),
            },
            default=str,
        )
        llm_result = cast(
            TriggerAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_INGEST_TRIGGERS,
                user_prompt=f"Trigger ingestion results:\n{ctx}",
                schema=TriggerAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} {len(triggers)} triggers."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="ingest_triggers",
        )

    step = ReasoningStep(
        step_number=1,
        action="ingest_triggers",
        input_summary="Ingesting security triggers from sources",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="trigger_ingester",
    )

    return {
        "triggers": [t.model_dump() for t in triggers],
        "trigger_count": len(triggers),
        "stage": SAHStage.MATCH_PLAYBOOKS,
        "session_start": start,
        "reasoning_chain": [step],
        "current_step": "ingest_triggers",
    }


# ---- Node: match_playbooks ----


async def match_playbooks(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Match triggers to appropriate playbooks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    triggers = [SecurityTrigger.model_validate(t) for t in state.triggers]

    logger.info(
        "sah_matching_playbooks",
        request_id=state.request_id,
        trigger_count=len(triggers),
    )

    matches = await toolkit.match_playbooks(triggers)
    approval_needed = sum(1 for m in matches if m.requires_approval)

    output_summary = f"Matched {len(matches)} playbooks. {approval_needed} require approval."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "triggers": len(triggers),
                "matches": len(matches),
                "approval_needed": approval_needed,
                "playbooks": list({m.playbook_name for m in matches}),
                "avg_confidence": round(
                    sum(m.confidence for m in matches) / max(len(matches), 1),
                    3,
                ),
            },
            default=str,
        )
        llm_result = cast(
            PlaybookAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_MATCH_PLAYBOOKS,
                user_prompt=f"Playbook matching results:\n{ctx}",
                schema=PlaybookAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Coverage: {llm_result.coverage_assessment}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="match_playbooks",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="match_playbooks",
        input_summary=f"Matching playbooks for {len(triggers)} triggers",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="playbook_matcher",
    )

    return {
        "playbook_matches": [m.model_dump() for m in matches],
        "stage": SAHStage.EXECUTE_AUTOMATIONS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "match_playbooks",
    }


# ---- Node: execute_automations ----


async def execute_automations(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Execute matched playbook automations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.security_automation_hub.models import (
        PlaybookMatch,
    )

    matches = [PlaybookMatch.model_validate(m) for m in state.playbook_matches]

    logger.info(
        "sah_executing_automations",
        request_id=state.request_id,
        match_count=len(matches),
    )

    executions = await toolkit.execute_automations(matches)
    completed = sum(1 for e in executions if e.status == AutomationStatus.COMPLETED)

    output_summary = f"Executed {len(executions)} automations. {completed} completed."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "matches": len(matches),
                "executions": len(executions),
                "completed": completed,
                "statuses": [e.status.value for e in executions],
            },
            default=str,
        )
        llm_result = cast(
            ExecutionAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_EXECUTE_AUTOMATIONS,
                user_prompt=f"Automation execution results:\n{ctx}",
                schema=ExecutionAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Effectiveness: {llm_result.effectiveness}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="execute_automations",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_automations",
        input_summary=(f"Executing {len(matches)} playbook automations"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="automation_executor",
    )

    return {
        "executions": [e.model_dump() for e in executions],
        "automation_count": len(executions),
        "success_count": completed,
        "stage": SAHStage.VALIDATE_RESULTS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "execute_automations",
    }


# ---- Node: validate_results ----


async def validate_results(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Validate automation execution results."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions = [AutomationExecution.model_validate(e) for e in state.executions]

    logger.info(
        "sah_validating_results",
        request_id=state.request_id,
        execution_count=len(executions),
    )

    validations = await toolkit.validate_results(executions)
    passed = sum(1 for v in validations if v.passed)

    output_summary = f"Validated {len(validations)} executions. {passed} passed."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "executions": len(executions),
                "validations": len(validations),
                "passed": passed,
                "issues": [issue for v in validations for issue in v.issues],
            },
            default=str,
        )
        llm_result = cast(
            ValidationAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_VALIDATE_RESULTS,
                user_prompt=f"Validation results:\n{ctx}",
                schema=ValidationAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Confidence: {llm_result.confidence}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_results",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="validate_results",
        input_summary=(f"Validating {len(executions)} execution results"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="result_validator",
    )

    return {
        "validations": [v.model_dump() for v in validations],
        "stage": SAHStage.LEARN_OUTCOMES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_results",
    }


# ---- Node: learn_outcomes ----


async def learn_outcomes(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Extract learning outcomes from automation cycle."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions = [AutomationExecution.model_validate(e) for e in state.executions]
    validations = [ValidationResult.model_validate(v) for v in state.validations]

    logger.info(
        "sah_learning_outcomes",
        request_id=state.request_id,
        execution_count=len(executions),
    )

    learnings = await toolkit.learn_outcomes(executions, validations)

    avg_score = round(
        sum(le.effectiveness_score for le in learnings) / max(len(learnings), 1),
        3,
    )

    output_summary = f"Learned from {len(learnings)} executions. Avg effectiveness: {avg_score}."

    # LLM enhancement
    try:
        import json

        ctx = json.dumps(
            {
                "learnings": len(learnings),
                "avg_effectiveness": avg_score,
                "lessons": [lesson for le in learnings for lesson in le.lessons],
            },
            default=str,
        )
        llm_result = cast(
            LearningAnalysis,
            await llm_structured(
                system_prompt=SYSTEM_LEARN_OUTCOMES,
                user_prompt=f"Learning outcomes:\n{ctx}",
                schema=LearningAnalysis,
            ),
        )
        output_summary = f"{llm_result.summary} Trend: {llm_result.overall_trend}."
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="learn_outcomes",
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="learn_outcomes",
        input_summary=(f"Learning from {len(executions)} automations"),
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="outcome_learner",
    )

    return {
        "learnings": [le.model_dump() for le in learnings],
        "stage": SAHStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "learn_outcomes",
    }


# ---- Node: generate_report ----


async def generate_report(
    state: SecurityAutomationHubState,
) -> dict[str, Any]:
    """Final reporting node -- summarize the automation cycle."""
    start = datetime.now(UTC)

    session_duration_ms = 0
    if state.session_start:
        session_duration_ms = _elapsed_ms(state.session_start)

    output_summary = (
        f"SAH cycle complete. "
        f"{state.trigger_count} triggers, "
        f"{len(state.playbook_matches)} playbooks matched, "
        f"{state.automation_count} automations, "
        f"{state.success_count} succeeded, "
        f"{len(state.validations)} validated. "
        f"Duration: {session_duration_ms}ms."
    )

    logger.info(
        "sah_report",
        request_id=state.request_id,
        summary=output_summary,
    )

    report = {
        "request_id": state.request_id,
        "tenant_id": state.tenant_id,
        "triggers_ingested": state.trigger_count,
        "playbooks_matched": len(state.playbook_matches),
        "automations_executed": state.automation_count,
        "automations_succeeded": state.success_count,
        "validations_passed": sum(1 for v in state.validations if v.get("passed", False)),
        "learnings_extracted": len(state.learnings),
        "duration_ms": session_duration_ms,
        "summary": output_summary,
    }

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary="Generating final automation hub report",
        output_summary=output_summary,
        duration_ms=_elapsed_ms(start),
        tool_used="report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": session_duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
