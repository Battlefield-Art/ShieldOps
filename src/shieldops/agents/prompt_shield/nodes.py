"""Node implementations for the Prompt Shield Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.prompt_shield.models import (
    DetectionVerdict,
    PromptShieldState,
    ReasoningStep,
    ShieldStage,
)
from shieldops.agents.prompt_shield.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_REPORT,
    ClassifyOutput,
    ReportOutput,
)
from shieldops.agents.prompt_shield.tools import PromptShieldToolkit
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PromptShieldToolkit | None = None


def _get_toolkit() -> PromptShieldToolkit:
    if _toolkit is None:
        return PromptShieldToolkit()
    return _toolkit


# ---------------------------------------------------------------------------
# Node: ingest_prompts
# ---------------------------------------------------------------------------


async def ingest_prompts(state: PromptShieldState) -> dict[str, Any]:
    """Ingest and normalize prompt samples for analysis."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_prompts = [p.model_dump() for p in state.prompts]
    ingested = await toolkit.ingest_prompts(raw_prompts)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="ingest_prompts",
        input_summary=f"Ingesting {len(raw_prompts)} prompt samples",
        output_summary=f"Ingested {len(ingested)} samples, "
        f"total chars={sum(s.get('char_count', 0) for s in ingested)}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="prompt_ingestor",
    )

    return {
        "total_scanned": len(ingested),
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.INGEST,
        "session_start": start,
    }


# ---------------------------------------------------------------------------
# Node: classify_threats
# ---------------------------------------------------------------------------


async def classify_threats(state: PromptShieldState) -> dict[str, Any]:
    """Classify each prompt sample by threat category."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_samples = [p.model_dump() for p in state.prompts]
    # Add decoded content for indirect injection scanning
    ingested = await toolkit.ingest_prompts(raw_samples)
    classifications = await toolkit.classify_threats(ingested)

    # LLM enhancement: refine classification for ambiguous cases
    for cls in classifications:
        if cls.get("max_confidence", 0) > 0 and cls.get("max_confidence", 0) < 0.85:
            try:
                sample_content = ""
                for p in state.prompts:
                    if p.sample_id == cls.get("sample_id"):
                        sample_content = p.content[:500]
                        break
                llm_result = await llm_structured(
                    system_prompt=SYSTEM_CLASSIFY,
                    user_prompt=f"Sample ID: {cls.get('sample_id')}\n"
                    f"Initial categories: {cls.get('categories')}\n"
                    f"Prompt content: {sample_content}",
                    schema=ClassifyOutput,
                )
                if hasattr(llm_result, "threat_categories"):
                    cls["categories"] = llm_result.threat_categories
                    cls["max_confidence"] = max(cls["max_confidence"], llm_result.confidence)
                    cls["llm_reasoning"] = llm_result.reasoning
                logger.info(
                    "llm_enhanced",
                    node="classify_threats",
                    sample_id=cls.get("sample_id"),
                )
            except Exception:
                logger.debug("llm_enhancement_skipped", node="classify_threats")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="classify_threats",
        input_summary=f"Classifying {len(raw_samples)} samples",
        output_summary=f"Classified {len(classifications)} samples, "
        f"{sum(1 for c in classifications if c.get('categories') != ['clean'])} flagged",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_classifier",
    )

    return {
        "classifications": classifications,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.CLASSIFY,
    }


# ---------------------------------------------------------------------------
# Node: detect_injections
# ---------------------------------------------------------------------------


async def detect_injections(state: PromptShieldState) -> dict[str, Any]:
    """Run detailed injection detection on all samples."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_samples = [p.model_dump() for p in state.prompts]
    ingested = await toolkit.ingest_prompts(raw_samples)
    detections = await toolkit.detect_injections(ingested)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="detect_injections",
        input_summary=f"Scanning {len(ingested)} samples for injections",
        output_summary=f"Found {len(detections)} injection detections",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="injection_detector",
    )

    return {
        "injection_detections": [d.model_dump() for d in detections],
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.DETECT_INJECTIONS,
    }


# ---------------------------------------------------------------------------
# Node: analyze_jailbreaks
# ---------------------------------------------------------------------------


async def analyze_jailbreaks(state: PromptShieldState) -> dict[str, Any]:
    """Analyze prompts for jailbreak techniques."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_samples = [p.model_dump() for p in state.prompts]
    ingested = await toolkit.ingest_prompts(raw_samples)
    attempts = await toolkit.analyze_jailbreaks(ingested)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_jailbreaks",
        input_summary=f"Analyzing {len(ingested)} samples for jailbreaks",
        output_summary=f"Found {len(attempts)} jailbreak attempts",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="jailbreak_analyzer",
    )

    return {
        "jailbreak_attempts": [a.model_dump() for a in attempts],
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.ANALYZE_JAILBREAKS,
    }


# ---------------------------------------------------------------------------
# Node: enforce_policies
# ---------------------------------------------------------------------------


async def enforce_policies(state: PromptShieldState) -> dict[str, Any]:
    """Enforce tenant policies based on all detections."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    from shieldops.agents.prompt_shield.models import InjectionDetection, JailbreakAttempt

    detections = [InjectionDetection.model_validate(d) for d in state.injection_detections]
    jailbreaks = [JailbreakAttempt.model_validate(j) for j in state.jailbreak_attempts]

    actions = await toolkit.enforce_policies(detections, jailbreaks, state.tenant_id)

    total_blocked = sum(1 for a in actions if a.action == "block")
    total_suspicious = sum(1 for a in actions if a.action == "flag")
    total_malicious = sum(1 for d in detections if d.verdict == DetectionVerdict.MALICIOUS) + sum(
        1 for j in jailbreaks if j.verdict == DetectionVerdict.MALICIOUS
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="enforce_policies",
        input_summary=f"Enforcing policies: {len(detections)} detections, "
        f"{len(jailbreaks)} jailbreaks",
        output_summary=f"Blocked={total_blocked}, flagged={total_suspicious}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="policy_engine",
    )

    return {
        "enforcement_actions": [a.model_dump() for a in actions],
        "total_blocked": total_blocked,
        "total_suspicious": total_suspicious,
        "total_malicious": total_malicious,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.ENFORCE_POLICIES,
    }


# ---------------------------------------------------------------------------
# Node: generate_report
# ---------------------------------------------------------------------------


async def generate_report(state: PromptShieldState) -> dict[str, Any]:
    """Generate a final analysis report."""
    start = datetime.now(UTC)

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    # Aggregate technique counts
    technique_counts: dict[str, int] = {}
    for det in state.injection_detections:
        pattern = (
            det.get("pattern_matched", "unknown") if isinstance(det, dict) else det.pattern_matched
        )  # type: ignore[union-attr]
        technique_counts[pattern] = technique_counts.get(pattern, 0) + 1
    for jb in state.jailbreak_attempts:
        technique = jb.get("technique", "unknown") if isinstance(jb, dict) else jb.technique  # type: ignore[union-attr]
        technique_counts[technique] = technique_counts.get(technique, 0) + 1

    top_techniques = sorted(technique_counts, key=technique_counts.get, reverse=True)[:5]  # type: ignore[arg-type]

    # Determine risk level
    if state.total_blocked >= 3 or state.total_malicious >= 2:
        risk_level = "critical"
    elif state.total_blocked >= 1 or state.total_malicious >= 1:
        risk_level = "high"
    elif state.total_suspicious >= 2:
        risk_level = "medium"
    elif state.total_suspicious >= 1:
        risk_level = "low"
    else:
        risk_level = "none"

    report: dict[str, Any] = {
        "scan_id": state.scan_id,
        "tenant_id": state.tenant_id,
        "total_scanned": state.total_scanned,
        "total_blocked": state.total_blocked,
        "total_suspicious": state.total_suspicious,
        "total_malicious": state.total_malicious,
        "risk_level": risk_level,
        "top_techniques": top_techniques,
        "technique_counts": technique_counts,
        "injection_count": len(state.injection_detections),
        "jailbreak_count": len(state.jailbreak_attempts),
        "enforcement_count": len(state.enforcement_actions),
        "duration_ms": duration_ms,
    }

    # LLM enhancement: generate executive summary
    try:
        report_context = _json.dumps(
            {
                "total_scanned": state.total_scanned,
                "total_blocked": state.total_blocked,
                "total_malicious": state.total_malicious,
                "total_suspicious": state.total_suspicious,
                "risk_level": risk_level,
                "top_techniques": top_techniques,
                "technique_counts": technique_counts,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Scan results:\n{report_context}",
            schema=ReportOutput,
        )
        if hasattr(llm_result, "summary"):
            report["summary"] = llm_result.summary
            report["recommendations"] = llm_result.recommendations
        logger.info("llm_enhanced", node="generate_report", risk_level=risk_level)
    except Exception:
        report["summary"] = (
            f"Scanned {state.total_scanned} prompts: "
            f"{state.total_blocked} blocked, {state.total_malicious} malicious, "
            f"{state.total_suspicious} suspicious. Risk level: {risk_level}."
        )
        report["recommendations"] = []
        logger.debug("llm_enhancement_skipped", node="generate_report")

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_report",
        input_summary=f"Generating report: {state.total_scanned} scanned, "
        f"{state.total_blocked} blocked",
        output_summary=f"Risk={risk_level}, techniques={len(top_techniques)}",
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="llm",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": ShieldStage.COMPLETE,
    }
