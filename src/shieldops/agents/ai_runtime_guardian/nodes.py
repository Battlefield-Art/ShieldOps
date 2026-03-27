"""AI Runtime Guardian Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog
from pydantic import BaseModel

from shieldops.utils.llm import llm_structured

from .models import (
    GuardianStage,
    GuardrailAction,
    GuardrailEnforcement,
    PromptAttackDetection,
    ReasoningStep,
    RuntimeMonitor,
    ToolExecutionGuard,
)
from .tools import AIRuntimeGuardianToolkit

logger = structlog.get_logger()


def _to_dict(state: Any) -> dict[str, Any]:
    if isinstance(state, BaseModel):
        return state.model_dump()
    return state  # type: ignore[no-any-return]


# ------------------------------------------------------------------
# Node 1: Monitor AI Runtime
# ------------------------------------------------------------------


async def monitor_ai_runtime(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Monitor AI agent runtimes."""
    logger.info("ai_guardian.node.monitor_runtime")
    state = _to_dict(state)

    tenant_id = state.get("tenant_id", "default")
    monitors = await toolkit.monitor_runtime(tenant_id)
    data = [m.model_dump() for m in monitors]

    note = f"Monitoring {len(monitors)} AI agents for tenant '{tenant_id}'"

    try:
        from .prompts import (
            SYSTEM_MONITOR,
            RuntimeInsight,
        )

        ctx = json.dumps(
            {
                "agents": [
                    {
                        "id": m.agent_id,
                        "model": m.model_name,
                        "anomaly": m.anomaly_score,
                        "status": m.status,
                    }
                    for m in monitors[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            RuntimeInsight,
            await llm_structured(
                system_prompt=SYSTEM_MONITOR,
                user_prompt=(f"Runtime monitors:\n{ctx}"),
                schema=RuntimeInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ai_guardian",
            node="monitor_runtime",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ai_guardian",
            node="monitor_runtime",
        )

    return {
        "stage": (GuardianStage.DETECT_PROMPT_ATTACKS.value),
        "monitors": data,
        "total_agents_monitored": len(monitors),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="monitor_ai_runtime",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 2: Detect Prompt Attacks
# ------------------------------------------------------------------


async def detect_prompt_attacks(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Detect prompt injection attacks."""
    logger.info("ai_guardian.node.detect_attacks")
    state = _to_dict(state)

    monitors = [RuntimeMonitor(**m) for m in state.get("monitors", [])]
    attacks = await toolkit.detect_prompt_attacks(monitors)
    data = [a.model_dump() for a in attacks]

    blocked = sum(1 for a in attacks if a.blocked)
    note = f"Detected {len(attacks)} attacks, {blocked} blocked"

    try:
        from .prompts import (
            SYSTEM_ATTACK,
            AttackInsight,
        )

        ctx = json.dumps(
            {
                "attacks": [
                    {
                        "agent": a.agent_id,
                        "vector": (a.threat_vector.value),
                        "technique": a.technique,
                        "confidence": a.confidence,
                    }
                    for a in attacks[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            AttackInsight,
            await llm_structured(
                system_prompt=SYSTEM_ATTACK,
                user_prompt=f"Attacks:\n{ctx}",
                schema=AttackInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ai_guardian",
            node="detect_attacks",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ai_guardian",
            node="detect_attacks",
        )

    return {
        "stage": (GuardianStage.ANALYZE_MODEL_BEHAVIOR.value),
        "attacks": data,
        "attacks_blocked": blocked,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="detect_prompt_attacks",
                detail=note,
                confidence=0.85,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 3: Analyze Model Behavior
# ------------------------------------------------------------------


async def analyze_model_behavior(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Analyze AI model behavioral patterns."""
    logger.info("ai_guardian.node.analyze_behavior")
    state = _to_dict(state)

    monitors = [RuntimeMonitor(**m) for m in state.get("monitors", [])]
    behaviors = await toolkit.analyze_model_behavior(monitors)
    data = [b.model_dump() for b in behaviors]

    note = f"Analyzed {len(behaviors)} model behaviors"

    try:
        from .prompts import (
            SYSTEM_BEHAVIOR,
            BehaviorInsight,
        )

        ctx = json.dumps(
            {
                "behaviors": [
                    {
                        "agent": b.agent_id,
                        "drift": b.drift_score,
                        "hallucination": (b.hallucination_rate),
                        "flags": b.behavioral_flags,
                    }
                    for b in behaviors[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            BehaviorInsight,
            await llm_structured(
                system_prompt=SYSTEM_BEHAVIOR,
                user_prompt=f"Behaviors:\n{ctx}",
                schema=BehaviorInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ai_guardian",
            node="analyze_behavior",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ai_guardian",
            node="analyze_behavior",
        )

    return {
        "stage": (GuardianStage.GUARD_TOOL_EXECUTION.value),
        "behaviors": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="analyze_model_behavior",
                detail=note,
                confidence=0.82,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 4: Guard Tool Execution
# ------------------------------------------------------------------


async def guard_tool_execution(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Guard AI tool execution calls."""
    logger.info("ai_guardian.node.guard_tools")
    state = _to_dict(state)

    monitors = [RuntimeMonitor(**m) for m in state.get("monitors", [])]
    attacks = [PromptAttackDetection(**a) for a in state.get("attacks", [])]
    guards = await toolkit.guard_tool_execution(monitors, attacks)
    data = [g.model_dump() for g in guards]

    blocked = sum(1 for g in guards if g.action_taken == GuardrailAction.BLOCK)
    note = f"Guarded {len(guards)} tool calls, {blocked} blocked"

    return {
        "stage": (GuardianStage.ENFORCE_GUARDRAILS.value),
        "tool_guards": data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="guard_tool_execution",
                detail=note,
                confidence=0.88,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 5: Enforce Guardrails
# ------------------------------------------------------------------


async def enforce_guardrails(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Enforce guardrail policies."""
    logger.info("ai_guardian.node.enforce_guardrails")
    state = _to_dict(state)

    attacks = [PromptAttackDetection(**a) for a in state.get("attacks", [])]
    tool_guards = [ToolExecutionGuard(**g) for g in state.get("tool_guards", [])]
    enforcements = await toolkit.enforce_guardrails(attacks, tool_guards)
    data = [e.model_dump() for e in enforcements]

    note = f"Enforced {len(enforcements)} guardrails"

    try:
        from .prompts import (
            SYSTEM_GUARDRAIL,
            GuardrailInsight,
        )

        ctx = json.dumps(
            {
                "enforcements": [
                    {
                        "agent": e.agent_id,
                        "rule": e.rule_name,
                        "action": e.action.value,
                        "threat": (e.threat_vector.value),
                    }
                    for e in enforcements[:20]
                ],
            },
            default=str,
        )
        llm_result = cast(
            GuardrailInsight,
            await llm_structured(
                system_prompt=SYSTEM_GUARDRAIL,
                user_prompt=(f"Enforcements:\n{ctx}"),
                schema=GuardrailInsight,
            ),
        )
        logger.info(
            "llm_enhanced",
            agent="ai_guardian",
            node="enforce_guardrails",
        )
        note = f"{llm_result.summary} {note}"
    except Exception:
        logger.debug(
            "llm_fallback",
            agent="ai_guardian",
            node="enforce_guardrails",
        )

    return {
        "stage": GuardianStage.REPORT.value,
        "enforcements": data,
        "guardrails_triggered": len(enforcements),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="enforce_guardrails",
                detail=note,
                confidence=0.9,
            ).model_dump()
        ],
    }


# ------------------------------------------------------------------
# Node 6: Report
# ------------------------------------------------------------------


async def report(
    state: dict[str, Any],
    toolkit: AIRuntimeGuardianToolkit,
) -> dict[str, Any]:
    """Compile the final AI runtime guardian report."""
    logger.info("ai_guardian.node.report")
    state = _to_dict(state)

    total = state.get("total_agents_monitored", 0)
    blocked = state.get("attacks_blocked", 0)
    triggered = state.get("guardrails_triggered", 0)
    attacks = state.get("attacks", [])
    enforcements = [GuardrailEnforcement(**e) for e in state.get("enforcements", [])]

    lines = [
        "# AI Runtime Guardian Report",
        "",
        f"**Agents monitored:** {total}",
        f"**Attacks detected:** {len(attacks)}",
        f"**Attacks blocked:** {blocked}",
        f"**Guardrails triggered:** {triggered}",
        "",
        "## Enforcements",
    ]
    for i, e in enumerate(enforcements[:15], 1):
        lines.append(f"{i}. [{e.action.value}] {e.agent_id} — {e.rule_name}: {e.details}")

    return {
        "stage": GuardianStage.REPORT.value,
        "report": "\n".join(lines),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            ReasoningStep(
                step="report",
                detail="Final report compiled",
                confidence=0.95,
            ).model_dump()
        ],
    }
