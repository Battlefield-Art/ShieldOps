"""Node implementations for the Quantum Safe Auditor."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.quantum_safe_auditor.models import (
    QSAStage,
    QuantumSafeAuditorState,
    ReasoningStep,
)
from shieldops.agents.quantum_safe_auditor.prompts import (
    SYSTEM_INVENTORY,
    SYSTEM_MIGRATION,
    SYSTEM_PROGRESS,
    SYSTEM_RISK,
    SYSTEM_VULNERABLE,
    CryptoInventoryOutput,
    MigrationPlanOutput,
    ProgressOutput,
    QuantumRiskOutput,
    VulnerabilityOutput,
)
from shieldops.agents.quantum_safe_auditor.tools import (
    QuantumSafeAuditorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: QuantumSafeAuditorToolkit | None = None


def set_toolkit(
    toolkit: QuantumSafeAuditorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> QuantumSafeAuditorToolkit:
    if _toolkit is None:
        return QuantumSafeAuditorToolkit()
    return _toolkit


def _step(
    state: QuantumSafeAuditorState,
    action: str,
    input_summary: str,
    output_summary: str,
    duration_ms: int,
    tool_used: str | None = None,
) -> ReasoningStep:
    """Create a reasoning step."""
    return ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action=action,
        input_summary=input_summary,
        output_summary=output_summary,
        duration_ms=duration_ms,
        tool_used=tool_used,
    )


async def inventory_crypto(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Inventory cryptographic assets across infrastructure."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.inventory_crypto(state.audit_config)
    total = len(raw)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.audit_config.get("scope", ""),
                "asset_count": total,
                "sample": raw[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_INVENTORY,
            user_prompt=f"Crypto inventory context:\n{ctx}",
            schema=CryptoInventoryOutput,
        )
        if hasattr(llm_result, "total_assets") and llm_result.total_assets > total:
            total = llm_result.total_assets
        logger.info(
            "llm_enhanced",
            node="inventory_crypto",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="inventory_crypto",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "inventory_crypto",
        f"scope={state.audit_config.get('scope', '')}",
        f"found {total} crypto assets",
        elapsed,
        "crypto_scanner",
    )
    await toolkit.record_metric("crypto_assets", float(total))

    return {
        "crypto_inventory": raw,
        "total_crypto_assets": total,
        "stage": QSAStage.ASSESS_QUANTUM_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "inventory_crypto",
        "session_start": start,
    }


async def assess_quantum_risk(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Assess quantum computing risk for crypto assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    risks = await toolkit.assess_quantum_risk(
        state.crypto_inventory,
    )
    high_count = sum(1 for r in risks if r.get("risk_score", 0) > 60)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.crypto_inventory),
                "risks": risks[:5],
                "high_risk": high_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=f"Quantum risk context:\n{ctx}",
            schema=QuantumRiskOutput,
        )
        if hasattr(llm_result, "high_risk_count") and llm_result.high_risk_count > high_count:
            high_count = llm_result.high_risk_count
        logger.info(
            "llm_enhanced",
            node="assess_quantum_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_quantum_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_quantum_risk",
        f"assessing {len(state.crypto_inventory)} crypto assets",
        f"{high_count} high quantum risk",
        elapsed,
        "risk_engine",
    )

    return {
        "quantum_risks": risks,
        "high_risk_count": high_count,
        "stage": QSAStage.IDENTIFY_VULNERABLE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_quantum_risk",
    }


async def identify_vulnerable(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Identify quantum-vulnerable cryptographic assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vulnerable = await toolkit.identify_vulnerable(
        state.crypto_inventory,
        state.quantum_risks,
    )
    vuln_count = len(vulnerable)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.crypto_inventory),
                "vulnerable": vulnerable[:5],
                "count": vuln_count,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_VULNERABLE,
            user_prompt=f"Vulnerability identification:\n{ctx}",
            schema=VulnerabilityOutput,
        )
        if hasattr(llm_result, "vulnerable_count") and llm_result.vulnerable_count > vuln_count:
            vuln_count = llm_result.vulnerable_count
        logger.info(
            "llm_enhanced",
            node="identify_vulnerable",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_vulnerable",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "identify_vulnerable",
        f"scanning {len(state.crypto_inventory)} assets",
        f"{vuln_count} quantum-vulnerable",
        elapsed,
        "crypto_scanner",
    )

    return {
        "vulnerable_assets": vulnerable,
        "vulnerable_count": vuln_count,
        "stage": QSAStage.PLAN_MIGRATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "identify_vulnerable",
    }


async def plan_migration(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Create migration plans for vulnerable assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    plans = await toolkit.plan_migration(
        state.vulnerable_assets,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "vulnerable_count": state.vulnerable_count,
                "plans": plans[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MIGRATION,
            user_prompt=f"Migration planning context:\n{ctx}",
            schema=MigrationPlanOutput,
        )
        if hasattr(llm_result, "plans"):
            logger.info(
                "llm_enhanced",
                node="plan_migration",
                plan_count=len(llm_result.plans),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="plan_migration",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "plan_migration",
        f"planning for {state.vulnerable_count} vulnerable assets",
        f"created {len(plans)} migration plans",
        elapsed,
        "migration_planner",
    )

    return {
        "migration_plans": plans,
        "stage": QSAStage.TRACK_PROGRESS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "plan_migration",
    }


async def track_progress(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Track migration progress."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    progress = await toolkit.track_progress(
        state.migration_plans,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "plan_count": len(state.migration_plans),
                "progress": progress[:5],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PROGRESS,
            user_prompt=f"Progress tracking context:\n{ctx}",
            schema=ProgressOutput,
        )
        if hasattr(llm_result, "overall_percent"):
            logger.info(
                "llm_enhanced",
                node="track_progress",
                pct=llm_result.overall_percent,
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="track_progress",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "track_progress",
        f"tracking {len(state.migration_plans)} migrations",
        f"{len(progress)} progress entries",
        elapsed,
        "migration_planner",
    )

    return {
        "migration_progress": progress,
        "stage": QSAStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "track_progress",
    }


async def generate_report(
    state: QuantumSafeAuditorState,
) -> dict[str, Any]:
    """Generate final quantum-safe audit report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_crypto_assets": state.total_crypto_assets,
        "high_risk_count": state.high_risk_count,
        "vulnerable_count": state.vulnerable_count,
        "migration_plans": len(state.migration_plans),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric(
        "audit_duration_ms",
        float(duration_ms),
    )
    await toolkit.record_metric(
        "vulnerable_crypto",
        float(state.vulnerable_count),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing audit {state.request_id}",
        f"report complete in {duration_ms}ms",
        elapsed,
        None,
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
