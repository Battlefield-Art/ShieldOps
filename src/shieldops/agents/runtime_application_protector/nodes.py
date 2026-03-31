"""Node implementations for the Runtime Application
Protector Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.runtime_application_protector.models import (
    RAPStage,
    ReasoningStep,
    RuntimeApplicationProtectorState,
)
from shieldops.agents.runtime_application_protector.prompts import (
    SYSTEM_CLASSIFICATION,
    SYSTEM_DETECTION,
    SYSTEM_REPORT,
    AttackDetectionOutput,
    ProtectionReportOutput,
    ThreatClassificationOutput,
)
from shieldops.agents.runtime_application_protector.tools import (
    RuntimeApplicationProtectorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: RuntimeApplicationProtectorToolkit | None = None


def set_toolkit(
    toolkit: RuntimeApplicationProtectorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> RuntimeApplicationProtectorToolkit:
    if _toolkit is None:
        return RuntimeApplicationProtectorToolkit()
    return _toolkit


def _step(
    chain: list[ReasoningStep],
    action: str,
    input_summary: str,
    output_summary: str,
    start: datetime,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Build a reasoning step with duration."""
    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    return ReasoningStep(
        step_number=len(chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=elapsed,
        tool_used=tool_used,
    )


# ------------------------------------------------------------------
# Node: instrument_app
# ------------------------------------------------------------------


async def instrument_app(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Install RASP hooks into the target application
    for runtime interception."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results = await toolkit.instrument_app(
        target_app=state.target_app,
        language=state.language,
        framework=state.framework,
        endpoints=state.endpoints,
    )

    step = _step(
        state.reasoning_chain,
        "instrument_app",
        f"App={state.target_app}, lang={state.language}",
        f"Instrumented {len(results)} hooks",
        start,
        "instrumenter",
    )

    return {
        "instrumentation": results,
        "stage": RAPStage.INSTRUMENT_APP,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "instrument_app",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: monitor_runtime
# ------------------------------------------------------------------


async def monitor_runtime(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Collect runtime events from instrumented hooks."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    events = await toolkit.monitor_runtime(
        target_app=state.target_app,
        instrumentation=state.instrumentation,
    )

    step = _step(
        state.reasoning_chain,
        "monitor_runtime",
        f"Monitoring {len(state.instrumentation)} hooks",
        f"Captured {len(events)} runtime events",
        start,
        "runtime_monitor",
    )

    return {
        "runtime_events": events,
        "total_events": len(events),
        "stage": RAPStage.MONITOR_RUNTIME,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_runtime",
    }


# ------------------------------------------------------------------
# Node: detect_attacks
# ------------------------------------------------------------------


async def detect_attacks(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Analyze runtime events for attack patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    attacks = await toolkit.detect_attacks(
        runtime_events=state.runtime_events,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "app": state.target_app,
                "event_count": len(state.runtime_events),
                "events_sample": state.runtime_events[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_DETECTION,
            user_prompt=f"Detect attacks in events:\n{ctx}",
            schema=AttackDetectionOutput,
        )
        if llm_out.attacks:  # type: ignore[union-attr]
            attacks = [
                *attacks,
                *llm_out.attacks,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_attacks",
            count=len(llm_out.attacks),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_attacks",
        )

    step = _step(
        state.reasoning_chain,
        "detect_attacks",
        f"Analyzing {len(state.runtime_events)} events",
        f"Detected {len(attacks)} attacks",
        start,
        "attack_detector",
    )

    return {
        "detected_attacks": attacks,
        "attacks_detected": len(attacks),
        "stage": RAPStage.DETECT_ATTACKS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_attacks",
    }


# ------------------------------------------------------------------
# Node: classify_threat
# ------------------------------------------------------------------


async def classify_threat(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Classify each detected attack by category and
    severity."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications: list[dict[str, Any]] = []

    for attack in state.detected_attacks:
        result = await toolkit.classify_threat(attack=attack)

        # LLM enhancement per attack
        try:
            ctx = _json.dumps(
                {"attack": attack},
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_CLASSIFICATION,
                user_prompt=f"Classify attack:\n{ctx}",
                schema=ThreatClassificationOutput,
            )
            _rid = random.randint(1000, 9999)  # noqa: S311
            result = {
                "classification_id": f"llm-{_rid}",
                "attack_category": llm_out.attack_category,  # type: ignore[union-attr]
                "severity": llm_out.severity,  # type: ignore[union-attr]
                "confidence": llm_out.confidence,  # type: ignore[union-attr]
                "cwe_ids": llm_out.cwe_ids,  # type: ignore[union-attr]
                "description": llm_out.description,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="classify_threat",
                category=llm_out.attack_category,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="classify_threat",
            )

        classifications.append(result)

    step = _step(
        state.reasoning_chain,
        "classify_threat",
        f"Classifying {len(state.detected_attacks)} attacks",
        f"Classified {len(classifications)} threats",
        start,
        "classifier",
    )

    return {
        "classifications": classifications,
        "stage": RAPStage.CLASSIFY_THREAT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_threat",
    }


# ------------------------------------------------------------------
# Node: protect
# ------------------------------------------------------------------


async def protect(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Apply protection actions based on classifications."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    protections: list[dict[str, Any]] = []
    blocked = 0

    for i, classification in enumerate(state.classifications):
        attack = state.detected_attacks[i] if i < len(state.detected_attacks) else {}
        result = await toolkit.apply_protection(
            attack=attack,
            classification=classification,
            mode=state.protection_mode,
        )
        protections.append(result)
        if result.get("action") == "block":
            blocked += 1

    step = _step(
        state.reasoning_chain,
        "protect",
        f"Protecting against {len(state.classifications)} threats",
        f"Applied {len(protections)} actions, {blocked} blocked",
        start,
        "protector",
    )

    return {
        "protections": protections,
        "attacks_blocked": blocked,
        "stage": RAPStage.PROTECT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "protect",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: RuntimeApplicationProtectorState,
) -> dict[str, Any]:
    """Generate the final RASP protection report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute false positive rate
    total = len(state.detected_attacks)
    fp_rate = 0.0
    if total > 0:
        low_conf = sum(
            1 for c in state.classifications if hasattr(c, "get") and c.get("confidence", 1.0) < 0.3
        )
        fp_rate = low_conf / total

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    report: dict[str, Any] = {
        "app": state.target_app,
        "total_events": state.total_events,
        "attacks_detected": state.attacks_detected,
        "attacks_blocked": state.attacks_blocked,
        "false_positive_rate": fp_rate,
        "duration_ms": duration_ms,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "app": state.target_app,
                "total_events": state.total_events,
                "attacks_detected": state.attacks_detected,
                "attacks_blocked": state.attacks_blocked,
                "classifications": state.classifications[:10],
                "protections": state.protections[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate RASP report:\n{ctx}",
            schema=ProtectionReportOutput,
        )
        if isinstance(llm_out, ProtectionReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "top_attack_categories": llm_out.top_attack_categories,
                    "recommendations": llm_out.recommendations,
                    "risk_rating": llm_out.risk_rating,
                }
            )
            logger.info(
                "llm_enhanced",
                node="generate_report",
                recommendations=len(llm_out.recommendations),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    # Record metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "attacks_detected": state.attacks_detected,
            "attacks_blocked": state.attacks_blocked,
            "false_positive_rate": fp_rate,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.attacks_detected} attacks",
        f"Report generated, blocked={state.attacks_blocked}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "false_positive_rate": fp_rate,
        "session_duration_ms": duration_ms,
        "stage": RAPStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
