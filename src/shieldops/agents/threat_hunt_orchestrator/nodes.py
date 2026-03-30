"""Node implementations for the Threat Hunt Orchestrator
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.threat_hunt_orchestrator.models import (
    ReasoningStep,
    THOStage,
    ThreatHuntOrchestratorState,
)
from shieldops.agents.threat_hunt_orchestrator.prompts import (
    SYSTEM_ANALYSIS,
    SYSTEM_HYPOTHESIS,
    SYSTEM_REPORT,
    SYSTEM_VALIDATION,
    DataAnalysisOutput,
    FindingValidationOutput,
    HuntReportOutput,
    HypothesisGenerationOutput,
)
from shieldops.agents.threat_hunt_orchestrator.tools import (
    ThreatHuntOrchestratorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ThreatHuntOrchestratorToolkit | None = None


def set_toolkit(
    toolkit: ThreatHuntOrchestratorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ThreatHuntOrchestratorToolkit:
    if _toolkit is None:
        return ThreatHuntOrchestratorToolkit()
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
# Node: generate_hypothesis
# ------------------------------------------------------------------


async def generate_hypothesis(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Generate hunt hypotheses from campaign scope and
    target MITRE ATT&CK tactics."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    tactics = [t.value for t in state.target_tactics]
    results = await toolkit.generate_hypotheses(
        scope=state.scope,
        tactics=tactics,
        hunt_type=state.hunt_type.value,
    )

    hypotheses: list[dict[str, Any]] = list(results)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "tactics": tactics,
                "scope": state.scope,
                "hunt_type": state.hunt_type.value,
                "data_sources": state.data_sources,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_HYPOTHESIS,
            user_prompt=(f"Generate hypotheses for:\n{ctx}"),
            schema=HypothesisGenerationOutput,
        )
        if llm_out.hypotheses:  # type: ignore[union-attr]
            hypotheses = [
                *hypotheses,
                *llm_out.hypotheses,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="generate_hypothesis",
            count=len(llm_out.hypotheses),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_hypothesis",
        )

    step = _step(
        state.reasoning_chain,
        "generate_hypothesis",
        f"Tactics: {len(tactics)}, type={state.hunt_type}",
        f"Generated {len(hypotheses)} hypotheses",
        start,
        "threat_intel",
    )

    return {
        "hypotheses": hypotheses,
        "stage": THOStage.GENERATE_HYPOTHESIS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "generate_hypothesis",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: collect_evidence
# ------------------------------------------------------------------


async def collect_evidence(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Query configured data sources for evidence
    matching the generated hypotheses."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    evidence = await toolkit.collect_evidence(
        data_sources=state.data_sources,
        scope=state.scope,
        hypotheses=state.hypotheses,
    )

    step = _step(
        state.reasoning_chain,
        "collect_evidence",
        (f"Querying {len(state.data_sources)} sources for {len(state.hypotheses)} hypotheses"),
        f"Collected {len(evidence)} evidence items",
        start,
        "data_collector",
    )

    return {
        "evidence": evidence,
        "stage": THOStage.COLLECT_EVIDENCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "collect_evidence",
    }


# ------------------------------------------------------------------
# Node: analyze_data
# ------------------------------------------------------------------


async def analyze_data(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Analyze collected evidence for anomalies and
    attack patterns."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    analyses = await toolkit.analyze_evidence(
        evidence=state.evidence,
        hypotheses=state.hypotheses,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "evidence_count": len(state.evidence),
                "evidence_sample": state.evidence[:5],
                "hypotheses": state.hypotheses[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_ANALYSIS,
            user_prompt=f"Analyze evidence:\n{ctx}",
            schema=DataAnalysisOutput,
        )
        if llm_out.patterns:  # type: ignore[union-attr]
            analyses.append(
                {
                    "analysis_id": f"llm-{random.randint(1000, 9999)}",  # noqa: S311
                    "anomalies_detected": (llm_out.anomalies_detected),  # type: ignore[union-attr]
                    "patterns": llm_out.patterns,  # type: ignore[union-attr]
                    "risk_score": llm_out.risk_score,  # type: ignore[union-attr]
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="analyze_data",
            patterns=len(llm_out.patterns),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_data",
        )

    step = _step(
        state.reasoning_chain,
        "analyze_data",
        f"Analyzing {len(state.evidence)} evidence items",
        f"Produced {len(analyses)} analysis results",
        start,
        "evidence_analyzer",
    )

    return {
        "analyses": analyses,
        "stage": THOStage.ANALYZE_DATA,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "analyze_data",
    }


# ------------------------------------------------------------------
# Node: validate_findings
# ------------------------------------------------------------------


async def validate_findings(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Validate analysis results against MITRE ATT&CK
    technique definitions."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    findings: list[dict[str, Any]] = []
    validated_count = 0

    # Extract MITRE techniques from hypotheses
    all_techniques: list[str] = []
    for hyp in state.hypotheses:
        techs = hyp.get("mitre_techniques", [])
        if isinstance(techs, list):
            all_techniques.extend(techs)

    for analysis in state.analyses:
        result = await toolkit.validate_finding(
            finding=analysis,
            mitre_techniques=all_techniques,
        )

        # LLM enhancement per finding
        try:
            ctx = _json.dumps(
                {
                    "analysis": analysis,
                    "mitre_techniques": all_techniques[:10],
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_VALIDATION,
                user_prompt=(f"Validate finding:\n{ctx}"),
                schema=FindingValidationOutput,
            )
            result = {
                "validated": llm_out.validated,  # type: ignore[union-attr]
                "severity": llm_out.severity,  # type: ignore[union-attr]
                "confidence": llm_out.confidence,  # type: ignore[union-attr]
                "mitre_technique": llm_out.mitre_mapping,  # type: ignore[union-attr]
                "description": llm_out.description,  # type: ignore[union-attr]
                "affected_assets": llm_out.affected_assets,  # type: ignore[union-attr]
            }
            logger.info(
                "llm_enhanced",
                node="validate_findings",
                validated=llm_out.validated,  # type: ignore[union-attr]
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="validate_findings",
            )

        findings.append(result)
        if result.get("validated"):
            validated_count += 1

    threat_found = validated_count > 0

    step = _step(
        state.reasoning_chain,
        "validate_findings",
        f"Validating {len(state.analyses)} analyses",
        (f"{validated_count} validated of {len(findings)} findings"),
        start,
        "mitre_validator",
    )

    return {
        "findings": findings,
        "threat_found": threat_found,
        "total_findings": len(findings),
        "validated_findings": validated_count,
        "stage": THOStage.VALIDATE_FINDINGS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "validate_findings",
    }


# ------------------------------------------------------------------
# Node: document_hunt
# ------------------------------------------------------------------


async def document_hunt(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Produce structured documentation for the completed
    hunt campaign."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    campaign_info = {
        "name": state.campaign_name,
        "hunt_type": state.hunt_type.value,
        "scope": state.scope,
        "hypotheses_count": len(state.hypotheses),
    }

    documentation = await toolkit.document_hunt(
        campaign=campaign_info,
        findings=state.findings,
    )

    # Enrich with computed metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    documentation.update(
        {
            "hunt_type": state.hunt_type.value,
            "findings_count": state.total_findings,
            "validated_count": state.validated_findings,
            "duration_ms": duration_ms,
        }
    )

    step = _step(
        state.reasoning_chain,
        "document_hunt",
        (f"Documenting {state.total_findings} findings, {state.validated_findings} validated"),
        "Hunt documentation produced",
        start,
        "documentation",
    )

    return {
        "documentation": documentation,
        "session_duration_ms": duration_ms,
        "stage": THOStage.DOCUMENT_HUNT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "document_hunt",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: ThreatHuntOrchestratorState,
) -> dict[str, Any]:
    """Generate the final hunt campaign report with
    executive summary and recommendations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute effectiveness
    if state.validated_findings > 0:
        effectiveness = min(
            1.0,
            0.5 + (state.validated_findings * 0.1),
        )
    elif state.total_findings > 0:
        effectiveness = min(0.5, state.total_findings * 0.1)
    else:
        effectiveness = 0.1

    report = await toolkit.generate_report(
        documentation=state.documentation,
        findings=state.findings,
        effectiveness=effectiveness,
    )

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "campaign": state.campaign_name,
                "hunt_type": state.hunt_type.value,
                "hypotheses_count": len(state.hypotheses),
                "total_findings": state.total_findings,
                "validated_findings": state.validated_findings,
                "findings_sample": state.findings[:5],
                "documentation": state.documentation,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate hunt report:\n{ctx}"),
            schema=HuntReportOutput,
        )
        if isinstance(llm_out, HuntReportOutput):
            report.update(
                {
                    "executive_summary": llm_out.executive_summary,
                    "recommendations": llm_out.recommendations,
                    "mitre_coverage": llm_out.mitre_coverage,
                    "effectiveness_rating": llm_out.effectiveness_rating,
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

    # Track effectiveness
    await toolkit.track_effectiveness(
        hunt_id=state.request_id,
        outcome={
            "threat_found": state.threat_found,
            "total_findings": state.total_findings,
            "validated_findings": state.validated_findings,
            "effectiveness": effectiveness,
            "duration_ms": state.session_duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_findings} findings"),
        (f"Report generated, effectiveness={effectiveness:.2f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "effectiveness_score": effectiveness,
        "stage": THOStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
