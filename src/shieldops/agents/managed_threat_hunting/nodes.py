"""Node implementations for the Managed Threat Hunting Agent."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.managed_threat_hunting.models import (
    HuntAnalysis,
    HuntExecution,
    HuntLead,
    HuntTechnique,
    ManagedThreatHuntingState,
    ReasoningStep,
    TelemetryCollection,
    ThreatAssessment,
    ThreatEscalation,
)
from shieldops.agents.managed_threat_hunting.prompts import (
    SYSTEM_ESCALATION_NARRATIVE,
    SYSTEM_FINDING_ANALYSIS,
    SYSTEM_LEAD_GENERATION,
    EscalationNarrativeOutput,
    FindingAnalysisOutput,
    HuntLeadOutput,
)
from shieldops.agents.managed_threat_hunting.tools import (
    ManagedThreatHuntingToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ManagedThreatHuntingToolkit | None = None


def set_toolkit(
    toolkit: ManagedThreatHuntingToolkit,
) -> None:
    """Set the global toolkit instance."""
    global _toolkit
    _toolkit = toolkit


def _get_toolkit() -> ManagedThreatHuntingToolkit:
    if _toolkit is None:
        return ManagedThreatHuntingToolkit()
    return _toolkit


async def generate_hunt_leads(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Generate prioritized hunt leads from threat intel."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw_leads = await toolkit.generate_hunt_leads(
        state.hunt_scope,
        state.vendor_sources,
    )

    # LLM enhancement: generate intelligent leads
    leads: list[HuntLead] = []
    try:
        import json as _json

        context = _json.dumps(
            {
                "scope": state.hunt_scope,
                "vendors": state.vendor_sources,
                "existing_leads": len(raw_leads),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_LEAD_GENERATION,
            user_prompt=(f"Environment context:\n{context}"),
            schema=HuntLeadOutput,
        )
        for _i, lead_data in enumerate(getattr(llm_result, "leads", [])):
            leads.append(
                HuntLead(
                    lead_id=f"lead-{uuid4().hex[:8]}",
                    title=lead_data.get("title", ""),
                    technique=HuntTechnique(
                        lead_data.get(
                            "technique",
                            "hypothesis_driven",
                        )
                    )
                    if lead_data.get("technique") in [e.value for e in HuntTechnique]
                    else HuntTechnique.HYPOTHESIS_DRIVEN,
                    hypothesis=lead_data.get("hypothesis", ""),
                    priority=lead_data.get("priority", "medium"),
                    mitre_techniques=getattr(llm_result, "mitre_techniques", []),
                )
            )
        logger.info(
            "llm_enhanced",
            node="generate_hunt_leads",
            lead_count=len(leads),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="generate_hunt_leads",
        )

    # Fallback: build leads from raw toolkit results
    if not leads:
        for raw in raw_leads:
            leads.append(
                HuntLead(
                    lead_id=raw.get(
                        "lead_id",
                        f"lead-{uuid4().hex[:8]}",
                    ),
                    title=raw.get("title", ""),
                    technique=HuntTechnique.HYPOTHESIS_DRIVEN,
                    hypothesis=raw.get("hypothesis", ""),
                    priority=raw.get("priority", "medium"),
                )
            )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="generate_hunt_leads",
        input_summary=(f"Scope: {len(state.vendor_sources)} vendors"),
        output_summary=(f"Generated {len(leads)} hunt leads"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="threat_intel",
    )

    return {
        "hunt_leads": leads,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "generate_hunt_leads",
        "session_start": start,
    }


async def collect_telemetry(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Collect telemetry from all configured vendors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    raw = await toolkit.collect_telemetry(
        state.vendor_sources,
        state.hunt_scope,
    )

    collections: list[TelemetryCollection] = []
    for entry in raw:
        collections.append(
            TelemetryCollection(
                collection_id=entry.get(
                    "collection_id",
                    f"col-{uuid4().hex[:8]}",
                ),
                vendor=entry.get("vendor", "unknown"),
                source_type=entry.get("source_type", "logs"),
                record_count=entry.get("record_count", 0),
                coverage_domains=entry.get("coverage_domains", []),
            )
        )

    # Compute coverage percentage
    all_domains = {
        "endpoint",
        "network",
        "identity",
        "cloud",
    }
    covered = set()
    for col in collections:
        covered.update(col.coverage_domains)
    coverage = len(covered & all_domains) / len(all_domains) * 100

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="collect_telemetry",
        input_summary=(f"Collecting from {len(state.vendor_sources)} vendors"),
        output_summary=(f"{len(collections)} collections, {coverage:.0f}% domain coverage"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="telemetry_collector",
    )

    return {
        "telemetry_collected": collections,
        "coverage_pct": coverage,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "collect_telemetry",
    }


async def execute_hunts(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Execute hunts for each lead against telemetry."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    executions: list[HuntExecution] = []
    telemetry_dicts = [t.model_dump() for t in state.telemetry_collected]

    for lead in state.hunt_leads:
        result = await toolkit.execute_hunt(
            lead.model_dump(),
            telemetry_dicts,
        )
        executions.append(
            HuntExecution(
                execution_id=result.get(
                    "execution_id",
                    f"exec-{uuid4().hex[:8]}",
                ),
                lead_id=lead.lead_id,
                technique=lead.technique,
                hits=result.get("hits", 0),
                artifacts=result.get("artifacts", []),
                status=result.get("status", "completed"),
                duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
            )
        )

    total_hits = sum(e.hits for e in executions)

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="execute_hunts",
        input_summary=(f"Executing {len(state.hunt_leads)} hunts"),
        output_summary=(f"{len(executions)} executions, {total_hits} total hits"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="hunt_engine",
    )

    hunts_per_day = len(executions) * (
        86400000
        / max(
            1,
            int((datetime.now(UTC) - start).total_seconds() * 1000),
        )
    )

    return {
        "hunts_executed": executions,
        "hunts_per_day": min(hunts_per_day, 9999.0),
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "execute_hunts",
    }


async def analyze_findings(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Analyze hunt execution results for threats."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    exec_dicts = [e.model_dump() for e in state.hunts_executed]
    raw_analyses = await toolkit.analyze_findings(exec_dicts)

    analyses: list[HuntAnalysis] = []

    # LLM-enhanced analysis
    try:
        import json as _json

        for execution in state.hunts_executed:
            if not execution.artifacts:
                continue
            context = _json.dumps(
                {
                    "lead_id": execution.lead_id,
                    "technique": execution.technique,
                    "hits": execution.hits,
                    "artifacts": execution.artifacts[:20],
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_FINDING_ANALYSIS,
                user_prompt=(f"Hunt execution findings:\n{context}"),
                schema=FindingAnalysisOutput,
            )
            assessment_val = getattr(llm_result, "assessment", "benign")
            if assessment_val in [e.value for e in ThreatAssessment]:
                ta = ThreatAssessment(assessment_val)
            else:
                ta = ThreatAssessment.BENIGN
            analyses.append(
                HuntAnalysis(
                    analysis_id=(f"ana-{uuid4().hex[:8]}"),
                    lead_id=execution.lead_id,
                    assessment=ta,
                    severity=getattr(llm_result, "severity", "low"),
                    confidence=getattr(llm_result, "confidence", 0.0),
                    affected_assets=getattr(
                        llm_result,
                        "affected_assets",
                        [],
                    ),
                    evidence_summary=getattr(llm_result, "summary", ""),
                    recommended_actions=getattr(
                        llm_result,
                        "recommended_actions",
                        [],
                    ),
                )
            )
        logger.info(
            "llm_enhanced",
            node="analyze_findings",
            analysis_count=len(analyses),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="analyze_findings",
        )

    # Fallback: from raw toolkit analyses
    if not analyses:
        for raw in raw_analyses:
            analyses.append(
                HuntAnalysis(
                    analysis_id=raw.get(
                        "analysis_id",
                        f"ana-{uuid4().hex[:8]}",
                    ),
                    lead_id=raw.get("lead_id", ""),
                    assessment=ThreatAssessment.BENIGN,
                    severity=raw.get("severity", "low"),
                    confidence=raw.get("confidence", 0.0),
                )
            )

    threats_found = sum(
        1
        for a in analyses
        if a.assessment
        in (
            ThreatAssessment.CONFIRMED,
            ThreatAssessment.PROBABLE,
        )
    )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="analyze_findings",
        input_summary=(f"Analyzing {len(state.hunts_executed)} execution results"),
        output_summary=(f"{len(analyses)} analyses, {threats_found} threats identified"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="finding_analyzer",
    )

    return {
        "findings": analyses,
        "threats_found": threats_found,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "analyze_findings",
    }


async def escalate_threats(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Escalate confirmed/probable threats to SOC/IR."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    escalations: list[ThreatEscalation] = []

    actionable = [
        f
        for f in state.findings
        if f.assessment
        in (
            ThreatAssessment.CONFIRMED,
            ThreatAssessment.PROBABLE,
        )
    ]

    for finding in actionable:
        # LLM-enhanced narrative generation
        title = finding.evidence_summary[:80]
        narrative = finding.evidence_summary
        response = finding.recommended_actions

        try:
            import json as _json

            context = _json.dumps(
                {
                    "assessment": finding.assessment,
                    "severity": finding.severity,
                    "affected_assets": (finding.affected_assets),
                    "evidence": finding.evidence_summary,
                    "mitre": finding.mitre_mapping,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=(SYSTEM_ESCALATION_NARRATIVE),
                user_prompt=(f"Threat finding:\n{context}"),
                schema=EscalationNarrativeOutput,
            )
            title = getattr(llm_result, "title", title)
            narrative = getattr(llm_result, "narrative", narrative)
            response = getattr(
                llm_result,
                "recommended_response",
                response,
            )
            logger.info(
                "llm_enhanced",
                node="escalate_threats",
                finding_id=finding.analysis_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="escalate_threats",
            )

        esc_result = await toolkit.escalate_threat(
            finding.model_dump(),
            {
                "title": title,
                "narrative": narrative,
            },
        )

        escalations.append(
            ThreatEscalation(
                escalation_id=esc_result.get(
                    "escalation_id",
                    f"esc-{uuid4().hex[:8]}",
                ),
                analysis_id=finding.analysis_id,
                assessment=finding.assessment,
                severity=finding.severity,
                title=title,
                narrative=narrative,
                evidence_package={
                    "affected_assets": (finding.affected_assets),
                    "mitre_mapping": (finding.mitre_mapping),
                    "confidence": finding.confidence,
                },
                recommended_response=response,
                escalated_to=esc_result.get("channels", []),
            )
        )

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="escalate_threats",
        input_summary=(f"{len(actionable)} actionable findings"),
        output_summary=(f"{len(escalations)} threats escalated"),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="escalation_service",
    )

    return {
        "escalations": escalations,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "escalate_threats",
    }


async def report(
    state: ManagedThreatHuntingState,
) -> dict[str, Any]:
    """Generate final hunt campaign report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    duration_ms = 0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)

    metrics = {
        "leads_generated": len(state.hunt_leads),
        "telemetry_collections": len(state.telemetry_collected),
        "hunts_executed": len(state.hunts_executed),
        "findings_analyzed": len(state.findings),
        "threats_found": state.threats_found,
        "escalations": len(state.escalations),
        "hunts_per_day": state.hunts_per_day,
        "coverage_pct": state.coverage_pct,
        "duration_ms": duration_ms,
    }

    report_data = await toolkit.generate_hunt_report(
        state.hunt_campaign_id,
        metrics,
    )
    report_data["metrics"] = metrics
    report_data["escalation_summary"] = [
        {
            "id": e.escalation_id,
            "title": e.title,
            "severity": e.severity,
            "assessment": e.assessment,
        }
        for e in state.escalations
    ]

    step = ReasoningStep(
        step_number=len(state.reasoning_chain) + 1,
        action="report",
        input_summary=(f"Campaign {state.hunt_campaign_id}"),
        output_summary=(
            f"Report generated: {state.threats_found} threats, {state.coverage_pct:.0f}% coverage"
        ),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
        tool_used="report_generator",
    )

    return {
        "report": report_data,
        "session_duration_ms": duration_ms,
        "reasoning_chain": [
            *state.reasoning_chain,
            step,
        ],
        "current_step": "complete",
    }
