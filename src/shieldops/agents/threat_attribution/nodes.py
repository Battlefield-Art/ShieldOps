"""Node implementations for the Threat Attribution LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.agents.threat_attribution.models import (
    AttributionStage,
    ConfidenceLevel,
    ThreatActorType,
    ThreatAttributionState,
)
from shieldops.agents.threat_attribution.prompts import (
    SYSTEM_ASSESS_CONFIDENCE,
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_GENERATE_REPORT,
    SYSTEM_MAP_TTPS,
    SYSTEM_PROFILE_ACTOR,
    ActorProfileOutput,
    ConfidenceOutput,
    EvidenceOutput,
    ReportOutput,
    TTPMappingOutput,
)
from shieldops.agents.threat_attribution.tools import (
    ThreatAttributionToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatAttributionToolkit | None = None


def set_toolkit(toolkit: ThreatAttributionToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatAttributionToolkit:
    if _toolkit is None:
        return ThreatAttributionToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: collect_evidence
# ------------------------------------------------------------------


async def collect_evidence(
    state: ThreatAttributionState,
) -> dict[str, Any]:
    """Collect IOCs and evidence for the incident."""
    start = time.time()
    toolkit = _get_toolkit()

    evidence = await toolkit.collect_evidence(state.incident_id)

    # LLM enhancement — extract structured indicators
    try:
        ctx = _json.dumps(
            {
                "incident_id": state.incident_id,
                "evidence": evidence,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_EVIDENCE,
            user_prompt=f"Collect evidence:\n{ctx}",
            schema=EvidenceOutput,
        )
        llm_indicators = getattr(llm_result, "indicators", [])
        if llm_indicators:
            for ind in llm_indicators:
                if isinstance(ind, dict) and ind not in evidence:
                    evidence.append(ind)
        logger.info("llm_enhanced", node="collect_evidence")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_evidence",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": AttributionStage.MAP_TTPS,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"Collected {len(evidence)} evidence item(s) in {elapsed}ms"),
            _json.dumps(
                {"_evidence": evidence},
                default=str,
            ),
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
    }


# ------------------------------------------------------------------
# Node: map_ttps
# ------------------------------------------------------------------


async def map_ttps(
    state: ThreatAttributionState,
) -> dict[str, Any]:
    """Map evidence to MITRE ATT&CK techniques."""
    start = time.time()
    toolkit = _get_toolkit()

    # Recover evidence from reasoning chain
    evidence: list[dict[str, Any]] = []
    for entry in reversed(state.reasoning_chain):
        if isinstance(entry, str) and '"_evidence"' in entry:
            try:
                parsed = _json.loads(entry)
                evidence = parsed.get("_evidence", [])
            except Exception:
                logger.debug("evidence_parse_failed")
            break

    # Fallback: re-collect if not found
    if not evidence:
        evidence = await toolkit.collect_evidence(
            state.incident_id,
        )

    mappings = await toolkit.map_ttps(evidence)

    # LLM enhancement — refine TTP mappings
    try:
        ctx = _json.dumps(
            {"evidence": evidence, "heuristic_ttps": [m.model_dump() for m in mappings]},
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_MAP_TTPS,
            user_prompt=f"Map TTPs:\n{ctx}",
            schema=TTPMappingOutput,
        )
        llm_techniques = getattr(llm_result, "techniques", [])
        if llm_techniques:
            logger.info(
                "llm_ttp_techniques",
                count=len(llm_techniques),
            )
        logger.info("llm_enhanced", node="map_ttps")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_ttps",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "ttp_mappings": mappings,
        "stage": AttributionStage.PROFILE_ACTOR,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"Mapped {len(mappings)} MITRE ATT&CK technique(s) in {elapsed}ms"),
        ],
    }


# ------------------------------------------------------------------
# Node: profile_actor
# ------------------------------------------------------------------


async def profile_actor(
    state: ThreatAttributionState,
) -> dict[str, Any]:
    """Profile the threat actor from TTP mappings."""
    start = time.time()
    toolkit = _get_toolkit()

    profile = await toolkit.profile_actor(state.ttp_mappings)

    # LLM enhancement — deeper actor profiling
    try:
        ctx = _json.dumps(
            {
                "ttp_mappings": [m.model_dump() for m in state.ttp_mappings],
                "heuristic_actor": profile.model_dump(),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_PROFILE_ACTOR,
            user_prompt=f"Profile actor:\n{ctx}",
            schema=ActorProfileOutput,
        )
        llm_actor = getattr(llm_result, "actor_name", "")
        if llm_actor and profile.name == "Unknown Actor":
            profile.name = llm_actor
        llm_type = getattr(llm_result, "actor_type", "")
        for at in ThreatActorType:
            if llm_type == at.value:
                profile.actor_type = at
                break
        logger.info("llm_enhanced", node="profile_actor")
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="profile_actor",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "actor_profile": profile,
        "stage": AttributionStage.ASSESS_CONFIDENCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"Profiled actor: {profile.name} ({profile.actor_type.value}) in {elapsed}ms"),
        ],
    }


# ------------------------------------------------------------------
# Node: assess_confidence
# ------------------------------------------------------------------


async def assess_confidence(
    state: ThreatAttributionState,
) -> dict[str, Any]:
    """Assess attribution confidence level."""
    start = time.time()
    toolkit = _get_toolkit()

    assessment = await toolkit.assess_confidence(
        state.ttp_mappings,
        state.actor_profile,
    )

    # LLM enhancement — refine confidence assessment
    try:
        ctx = _json.dumps(
            {
                "ttp_mappings": [m.model_dump() for m in state.ttp_mappings],
                "actor_profile": state.actor_profile.model_dump(),
                "heuristic_assessment": assessment.model_dump(),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_ASSESS_CONFIDENCE,
            user_prompt=f"Assess confidence:\n{ctx}",
            schema=ConfidenceOutput,
        )
        llm_conf = getattr(
            llm_result,
            "confidence_level",
            "",
        )
        for cl in ConfidenceLevel:
            if llm_conf == cl.value:
                assessment.confidence = cl
                break
        llm_evidence = getattr(
            llm_result,
            "supporting_evidence",
            [],
        )
        if llm_evidence:
            for ev in llm_evidence:
                if ev not in assessment.supporting_evidence:
                    assessment.supporting_evidence.append(ev)
        logger.info(
            "llm_enhanced",
            node="assess_confidence",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="assess_confidence",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "confidence": assessment.confidence,
        "attribution_assessment": assessment,
        "stage": AttributionStage.GENERATE_REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            (
                f"Confidence: {assessment.confidence.value} "
                f"for {assessment.attributed_actor} "
                f"({elapsed}ms)"
            ),
        ],
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThreatAttributionState,
) -> dict[str, Any]:
    """Generate the final attribution report."""
    start = time.time()
    total_elapsed = int(
        (time.time() - state.session_start) * 1000,
    )

    summary = (
        f"Threat attribution for {state.incident_id}: "
        f"actor={state.actor_profile.name}, "
        f"confidence={state.confidence.value}, "
        f"ttps={len(state.ttp_mappings)}"
    )

    # LLM enhancement — executive report
    try:
        ctx = _json.dumps(
            {
                "incident_id": state.incident_id,
                "actor_profile": (state.actor_profile.model_dump()),
                "confidence": state.confidence.value,
                "ttp_mappings": [m.model_dump() for m in state.ttp_mappings[:20]],
                "attribution_assessment": (state.attribution_assessment.model_dump()),
                "reasoning_chain": (state.reasoning_chain[-10:]),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_GENERATE_REPORT,
            user_prompt=(f"Generate attribution report:\n{ctx}"),
            schema=ReportOutput,
        )
        exec_summary = getattr(
            llm_result,
            "executive_summary",
            "",
        )
        if exec_summary:
            summary = exec_summary
        logger.info(
            "llm_enhanced",
            node="generate_report",
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_report",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": AttributionStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"Report generated in {elapsed}ms (total {total_elapsed}ms): {summary}"),
        ],
    }
