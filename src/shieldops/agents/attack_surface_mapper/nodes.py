"""Node implementations for the Attack Surface Mapper."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.attack_surface_mapper.models import (
    ASMStage,
    AttackSurfaceMapperState,
    ReasoningStep,
)
from shieldops.agents.attack_surface_mapper.prompts import (
    SYSTEM_ATTACK_PATHS,
    SYSTEM_CLASSIFY,
    SYSTEM_DISCOVER,
    SYSTEM_REMEDIATE,
    SYSTEM_RISK,
    AssetDiscoveryOutput,
    AttackPathOutput,
    ExposureClassifyOutput,
    RemediationOutput,
    RiskAssessmentOutput,
)
from shieldops.agents.attack_surface_mapper.tools import (
    AttackSurfaceMapperToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AttackSurfaceMapperToolkit | None = None


def set_toolkit(
    toolkit: AttackSurfaceMapperToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AttackSurfaceMapperToolkit:
    if _toolkit is None:
        return AttackSurfaceMapperToolkit()
    return _toolkit


def _step(
    state: AttackSurfaceMapperState,
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


async def discover_assets(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Discover external and internal assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.discover_assets(state.scan_config)
    shadow_count = sum(1 for a in raw if a.get("is_shadow_it"))

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "scope": state.scan_config.get("scope", ""),
                "targets": state.scan_config.get("targets", [])[:10],
                "asset_count": len(raw),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_DISCOVER,
            user_prompt=(f"Asset discovery context:\n{ctx}"),
            schema=AssetDiscoveryOutput,
        )
        if hasattr(llm_result, "shadow_it_count") and llm_result.shadow_it_count > shadow_count:
            shadow_count = llm_result.shadow_it_count
        logger.info(
            "llm_enhanced",
            node="discover_assets",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="discover_assets",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "discover_assets",
        f"scope={state.scan_config.get('scope', '')}",
        f"found {len(raw)} assets, {shadow_count} shadow IT",
        elapsed,
        "dns_scanner",
    )
    await toolkit.record_metric("discovery", float(len(raw)))

    return {
        "discovered_assets": raw,
        "shadow_it_count": shadow_count,
        "stage": ASMStage.CLASSIFY_EXPOSURE,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "discover_assets",
        "session_start": start,
    }


async def classify_exposure(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Classify exposure level for each asset."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_exposure(
        state.discovered_assets,
    )
    inet_count = sum(1 for c in classifications if c.get("exposure_level") == "internet_facing")

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.discovered_assets),
                "classifications": classifications[:10],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Exposure classification:\n{ctx}"),
            schema=ExposureClassifyOutput,
        )
        if hasattr(llm_result, "internet_facing") and llm_result.internet_facing > inet_count:
            inet_count = llm_result.internet_facing
        logger.info(
            "llm_enhanced",
            node="classify_exposure",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_exposure",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "classify_exposure",
        f"classifying {len(state.discovered_assets)} assets",
        f"{inet_count} internet-facing",
        elapsed,
        "exposure_classifier",
    )

    return {
        "exposure_classifications": classifications,
        "internet_facing_count": inet_count,
        "stage": ASMStage.ASSESS_RISK,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "classify_exposure",
    }


async def assess_risk(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Assess risk for classified assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    assessments = await toolkit.assess_risk(
        state.exposure_classifications,
    )
    max_score = max(
        (a.get("risk_score", 0.0) for a in assessments),
        default=0.0,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "classification_count": len(state.exposure_classifications),
                "assessments": assessments[:10],
                "max_score": max_score,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_RISK,
            user_prompt=(f"Risk assessment context:\n{ctx}"),
            schema=RiskAssessmentOutput,
        )
        if hasattr(llm_result, "max_risk_score") and llm_result.max_risk_score > max_score:
            max_score = round(
                (max_score + llm_result.max_risk_score) / 2,
                1,
            )
        logger.info(
            "llm_enhanced",
            node="assess_risk",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_risk",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "assess_risk",
        f"assessing {len(state.exposure_classifications)} classified assets",
        f"max_risk={max_score}",
        elapsed,
        "vuln_scanner",
    )
    await toolkit.record_metric("max_risk", max_score)

    return {
        "risk_assessments": assessments,
        "max_risk_score": max_score,
        "stage": ASMStage.MAP_ATTACK_PATHS,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "assess_risk",
    }


async def map_attack_paths(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Map attack paths through discovered assets."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    paths = await toolkit.map_attack_paths(
        state.discovered_assets,
        state.risk_assessments,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "asset_count": len(state.discovered_assets),
                "risk_count": len(state.risk_assessments),
                "paths_found": len(paths),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ATTACK_PATHS,
            user_prompt=(f"Attack path mapping:\n{ctx}"),
            schema=AttackPathOutput,
        )
        if hasattr(llm_result, "paths"):
            logger.info(
                "llm_enhanced",
                node="map_attack_paths",
                llm_paths=len(llm_result.paths),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_attack_paths",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "map_attack_paths",
        f"mapping paths across {len(state.risk_assessments)} assessed assets",
        f"found {len(paths)} attack paths",
        elapsed,
        "path_mapper",
    )

    return {
        "attack_paths": paths,
        "stage": ASMStage.RECOMMEND_REMEDIATION,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "map_attack_paths",
    }


async def recommend_remediation(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Generate remediation recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    recs = await toolkit.generate_recommendations(
        state.risk_assessments,
        state.attack_paths,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "risk_count": len(state.risk_assessments),
                "path_count": len(state.attack_paths),
                "rec_count": len(recs),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REMEDIATE,
            user_prompt=(f"Remediation context:\n{ctx}"),
            schema=RemediationOutput,
        )
        if hasattr(llm_result, "actions"):
            logger.info(
                "llm_enhanced",
                node="recommend_remediation",
                llm_actions=len(llm_result.actions),
            )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="recommend_remediation",
        )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "recommend_remediation",
        f"generating recs for {len(state.risk_assessments)} risks",
        f"created {len(recs)} recommendations",
        elapsed,
        "remediation_engine",
    )

    return {
        "recommendations": recs,
        "stage": ASMStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "recommend_remediation",
    }


async def generate_report(
    state: AttackSurfaceMapperState,
) -> dict[str, Any]:
    """Generate final attack surface report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    report = {
        "request_id": state.request_id,
        "total_assets": len(state.discovered_assets),
        "shadow_it_count": state.shadow_it_count,
        "internet_facing": state.internet_facing_count,
        "max_risk_score": state.max_risk_score,
        "attack_paths": len(state.attack_paths),
        "recommendations": len(state.recommendations),
        "duration_ms": duration_ms,
    }

    await toolkit.record_metric("scan_duration_ms", float(duration_ms))
    await toolkit.record_metric(
        "total_assets",
        float(len(state.discovered_assets)),
    )

    elapsed = int((datetime.now(UTC) - start).total_seconds() * 1000)
    step = _step(
        state,
        "generate_report",
        f"finalizing scan {state.request_id}",
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
