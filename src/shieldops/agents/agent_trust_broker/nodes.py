"""Node implementations for the Agent Trust Broker."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.agent_trust_broker.models import (
    AgentTrustBrokerState,
    ATBStage,
    ReasoningStep,
)
from shieldops.agents.agent_trust_broker.prompts import (
    SYSTEM_MONITOR,
    SYSTEM_REGISTER,
    SYSTEM_REVOKE,
    SYSTEM_TRUST,
    SYSTEM_VALIDATE,
    BehaviorMonitorOutput,
    RegistrationOutput,
    RevocationOutput,
    TrustEstablishOutput,
    ValidationOutput,
)
from shieldops.agents.agent_trust_broker.tools import (
    AgentTrustBrokerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AgentTrustBrokerToolkit | None = None


def _get_toolkit() -> AgentTrustBrokerToolkit:
    if _toolkit is None:
        return AgentTrustBrokerToolkit()
    return _toolkit


def _step(
    state: AgentTrustBrokerState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def register_agents(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Register agents for trust brokering."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    regs = await toolkit.register_agents(state.config)

    try:
        ctx = _json.dumps(
            {"count": len(regs)},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REGISTER,
            user_prompt=f"Registration context:\n{ctx}",
            schema=RegistrationOutput,
        )
        if hasattr(llm_result, "agents_registered"):
            logger.info(
                "llm_enhanced",
                node="register_agents",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="register_agents",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "register_agents",
        f"config={state.config}",
        f"registered {len(regs)} agents",
        elapsed,
        "agent_registry",
    )
    await toolkit.record_metric(
        "agents_registered",
        float(len(regs)),
    )

    return {
        "registrations": regs,
        "stage": ATBStage.VALIDATE_IDENTITY,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "register_agents",
        "session_start": start,
    }


async def validate_identity(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Validate agent identities."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vals = await toolkit.validate_identity(
        state.registrations,
    )
    verified = sum(1 for v in vals if v.get("status") == "verified")

    try:
        ctx = _json.dumps(
            {
                "registrations": len(state.registrations),
                "verified": verified,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validation context:\n{ctx}",
            schema=ValidationOutput,
        )
        if hasattr(llm_result, "validated_count"):
            logger.info(
                "llm_enhanced",
                node="validate_identity",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="validate_identity",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "validate_identity",
        f"validating {len(state.registrations)} agents",
        f"{verified} verified",
        elapsed,
        "identity_service",
    )

    return {
        "validations": vals,
        "stage": ATBStage.ESTABLISH_TRUST,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_identity",
    }


async def establish_trust(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Establish trust relationships."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    rels = await toolkit.establish_trust(
        state.validations,
        state.config,
    )

    try:
        ctx = _json.dumps(
            {
                "validations": len(state.validations),
                "relationships": len(rels),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TRUST,
            user_prompt=f"Trust establishment context:\n{ctx}",
            schema=TrustEstablishOutput,
        )
        if hasattr(llm_result, "relationships_created"):
            logger.info(
                "llm_enhanced",
                node="establish_trust",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="establish_trust",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "establish_trust",
        f"establishing from {len(state.validations)} validations",
        f"{len(rels)} trust relationships",
        elapsed,
        "trust_engine",
    )
    await toolkit.record_metric(
        "trust_relationships",
        float(len(rels)),
    )

    return {
        "trust_relationships": rels,
        "stage": ATBStage.MONITOR_BEHAVIOR,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "establish_trust",
    }


async def monitor_behavior(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Monitor agent behavior for anomalies."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    records = await toolkit.monitor_behavior(
        state.trust_relationships,
    )
    high_risk = sum(1 for r in records if r.get("risk_level") == "high")

    try:
        ctx = _json.dumps(
            {
                "relationships": len(state.trust_relationships),
                "monitored": len(records),
                "high_risk": high_risk,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MONITOR,
            user_prompt=f"Behavior monitoring context:\n{ctx}",
            schema=BehaviorMonitorOutput,
        )
        if hasattr(llm_result, "agents_monitored"):
            logger.info(
                "llm_enhanced",
                node="monitor_behavior",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="monitor_behavior",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "monitor_behavior",
        f"monitoring {len(state.trust_relationships)} rels",
        f"{len(records)} records, {high_risk} high risk",
        elapsed,
        "behavior_monitor",
    )

    return {
        "behavior_records": records,
        "stage": ATBStage.REVOKE_COMPROMISED,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "monitor_behavior",
    }


async def revoke_compromised(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Revoke trust for compromised agents."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    revocations = await toolkit.revoke_compromised(
        state.behavior_records,
    )

    try:
        ctx = _json.dumps(
            {
                "behavior_records": len(state.behavior_records),
                "revocations": len(revocations),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REVOKE,
            user_prompt=f"Revocation context:\n{ctx}",
            schema=RevocationOutput,
        )
        if hasattr(llm_result, "revocations_issued"):
            logger.info(
                "llm_enhanced",
                node="revoke_compromised",
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="revoke_compromised",
        )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "revoke_compromised",
        f"checking {len(state.behavior_records)} records",
        f"{len(revocations)} revocations",
        elapsed,
        "trust_engine",
    )
    await toolkit.record_metric(
        "revocations",
        float(len(revocations)),
    )

    return {
        "revocations": revocations,
        "stage": ATBStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "revoke_compromised",
    }


async def generate_report(
    state: AgentTrustBrokerState,
) -> dict[str, Any]:
    """Generate final trust broker report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int(
            (datetime.now(UTC) - state.session_start).total_seconds() * 1000,
        )

    report = {
        "request_id": state.request_id,
        "agents_registered": len(state.registrations),
        "agents_validated": len(state.validations),
        "trust_relationships": len(state.trust_relationships),
        "behavior_records": len(state.behavior_records),
        "revocations": len(state.revocations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "scan_duration_ms",
        float(duration_ms),
    )

    elapsed = int(
        (datetime.now(UTC) - start).total_seconds() * 1000,
    )
    step = _step(
        state,
        "generate_report",
        f"finalizing {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
