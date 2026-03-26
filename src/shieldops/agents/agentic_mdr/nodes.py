"""Node implementations for the Agentic MDR LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.agentic_mdr.models import (
    AgenticMDRState,
    AlertIngestion,
    ClosedLoopImprovement,
    InvestigationDepth,
    InvestigationFinding,
    ResponseAction,
    ResponseDecision,
    TriageResult,
    ValidationResult,
)
from shieldops.agents.agentic_mdr.prompts import (
    SYSTEM_INVESTIGATE,
    SYSTEM_REPORT,
    SYSTEM_TRIAGE,
    InvestigateLLMOutput,
    ReportLLMOutput,
    TriageLLMOutput,
)
from shieldops.agents.agentic_mdr.tools import (
    AgenticMDRToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: AgenticMDRToolkit | None = None


def set_toolkit(toolkit: AgenticMDRToolkit) -> None:
    """Inject the toolkit instance used by nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> AgenticMDRToolkit:
    if _toolkit is None:
        return AgenticMDRToolkit()
    return _toolkit


# ---------------------------------------------------------------
# 1. ingest_alerts
# ---------------------------------------------------------------


async def ingest_alerts(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Pull and normalize alerts from all vendors."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    vendors = state.vendor_sources or [
        "crowdstrike",
        "defender",
        "wiz",
        "splunk",
        "elastic",
    ]

    normalized = await toolkit.ingest_alerts(
        vendors=vendors,
        raw_alerts=state.raw_alerts or None,
    )

    ingested = [AlertIngestion(**a) for a in normalized]

    logger.info(
        "agentic_mdr.ingest",
        alert_count=len(ingested),
        vendors=vendors,
    )

    return {
        "ingested_alerts": ingested,
        "vendor_sources": vendors,
        "alert_count": len(ingested),
        "current_stage": "ingest_alerts",
        "session_start": start,
    }


# ---------------------------------------------------------------
# 2. auto_triage
# ---------------------------------------------------------------


async def auto_triage(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Confidence-based auto-triage with LLM enhancement."""
    start = datetime.now(UTC)
    results: list[TriageResult] = []

    for alert in state.ingested_alerts:
        # Build triage context
        ctx = _json.dumps(
            {
                "alert_id": alert.alert_id,
                "vendor": alert.vendor,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "hostname": alert.hostname,
                "source_ip": alert.source_ip,
                "user": alert.user,
                "mitre_technique": alert.mitre_technique,
                "confidence": alert.confidence,
            },
            default=str,
        )

        # Defaults from raw confidence
        conf = alert.confidence
        decision = _confidence_decision(conf)
        depth = _depth_from_severity(alert.severity)
        mitre: list[str] = []
        if alert.mitre_technique:
            mitre = [alert.mitre_technique]
        reasoning = "rule-based triage"

        # LLM-enhanced triage
        try:
            llm_out = await llm_structured(
                system_prompt=SYSTEM_TRIAGE,
                user_prompt=(f"Triage this alert:\n{ctx}"),
                schema=TriageLLMOutput,
            )
            conf = getattr(llm_out, "confidence", conf)
            decision = ResponseDecision(
                getattr(
                    llm_out,
                    "decision",
                    decision.value,
                )
            )
            depth = InvestigationDepth(
                getattr(
                    llm_out,
                    "investigation_depth",
                    depth.value,
                )
            )
            mitre = getattr(llm_out, "mitre_techniques", mitre)
            reasoning = getattr(llm_out, "reasoning", reasoning)
            logger.info(
                "llm_enhanced",
                node="auto_triage",
                alert_id=alert.alert_id,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="auto_triage",
                alert_id=alert.alert_id,
            )

        results.append(
            TriageResult(
                alert_id=alert.alert_id,
                priority=alert.severity,
                confidence=conf,
                decision=decision,
                investigation_depth=depth,
                mitre_techniques=mitre,
                reasoning=reasoning,
                suppressed=(decision == ResponseDecision.SUPPRESS),
            )
        )

    logger.info(
        "agentic_mdr.triage",
        triaged=len(results),
        auto=sum(1 for r in results if r.decision == ResponseDecision.AUTO_REMEDIATE),
        duration_ms=int((datetime.now(UTC) - start).total_seconds() * 1000),
    )

    return {
        "triage_results": results,
        "current_stage": "auto_triage",
    }


# ---------------------------------------------------------------
# 3. investigate
# ---------------------------------------------------------------


async def investigate(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Cross-vendor investigation with signal correlation."""
    toolkit = _get_toolkit()

    # Filter out suppressed alerts
    active = [t for t in state.triage_results if not t.suppressed]
    if not active:
        return {
            "findings": [],
            "current_stage": "investigate",
        }

    # Cross-vendor correlation
    alert_dicts = [a.model_dump() for a in state.ingested_alerts]
    correlated = await toolkit.correlate_signals(alert_dicts)

    # Enrich with threat intel
    iocs: list[str] = []
    for a in state.ingested_alerts:
        if a.source_ip:
            iocs.append(a.source_ip)
    enrichment: dict[str, Any] = {}
    if iocs:
        enrichment = await toolkit.enrich_with_threat_intel(iocs)

    # LLM-enhanced investigation
    findings: list[InvestigationFinding] = []
    for corr in correlated:
        try:
            inv_ctx = _json.dumps(
                {
                    "correlation": corr,
                    "enrichment": enrichment,
                    "triage_decisions": [
                        {
                            "alert_id": t.alert_id,
                            "decision": t.decision.value,
                            "confidence": t.confidence,
                        }
                        for t in active
                    ],
                },
                default=str,
            )
            llm_out = await llm_structured(
                system_prompt=SYSTEM_INVESTIGATE,
                user_prompt=(f"Investigate:\n{inv_ctx}"),
                schema=InvestigateLLMOutput,
            )
            findings.append(
                InvestigationFinding(
                    finding_id=corr.get("finding_id", ""),
                    alert_ids=corr.get("alert_ids", []),
                    vendors_correlated=corr.get("vendors_correlated", []),
                    description=getattr(
                        llm_out,
                        "description",
                        corr.get("description", ""),
                    ),
                    severity=getattr(
                        llm_out,
                        "severity",
                        corr.get("severity", "medium"),
                    ),
                    kill_chain_phase=getattr(
                        llm_out,
                        "kill_chain_phase",
                        "",
                    ),
                    mitre_techniques=getattr(
                        llm_out,
                        "mitre_techniques",
                        corr.get("mitre_techniques", []),
                    ),
                    affected_assets=corr.get("affected_assets", []),
                    ioc_indicators=getattr(
                        llm_out,
                        "ioc_indicators",
                        corr.get("ioc_indicators", []),
                    ),
                    confidence=getattr(
                        llm_out,
                        "confidence",
                        corr.get("confidence", 0.5),
                    ),
                    enrichment=enrichment,
                )
            )
            logger.info(
                "llm_enhanced",
                node="investigate",
                finding_id=corr.get("finding_id"),
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="investigate",
            )
            findings.append(InvestigationFinding(**corr))

    # Add single-alert findings for uncorrelated
    correlated_ids: set[str] = set()
    for f in findings:
        correlated_ids.update(f.alert_ids)
    for alert in state.ingested_alerts:
        if alert.alert_id not in correlated_ids:
            triage = next(
                (t for t in active if t.alert_id == alert.alert_id),
                None,
            )
            if triage and not triage.suppressed:
                findings.append(
                    InvestigationFinding(
                        finding_id=(f"find-{alert.alert_id}"),
                        alert_ids=[alert.alert_id],
                        vendors_correlated=[alert.vendor],
                        description=alert.description,
                        severity=alert.severity,
                        mitre_techniques=(triage.mitre_techniques),
                        affected_assets=([alert.hostname] if alert.hostname else []),
                        confidence=triage.confidence,
                        enrichment=enrichment,
                    )
                )

    return {
        "findings": findings,
        "current_stage": "investigate",
    }


# ---------------------------------------------------------------
# 4. decide_response
# ---------------------------------------------------------------


async def decide_response(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Map triage decisions to response actions."""
    actions: list[ResponseAction] = []
    escalations: list[dict[str, Any]] = []

    triage_map: dict[str, TriageResult] = {t.alert_id: t for t in state.triage_results}

    for finding in state.findings:
        # Use highest-confidence triage decision
        decisions = [triage_map[aid] for aid in finding.alert_ids if aid in triage_map]
        if not decisions:
            continue
        best = max(decisions, key=lambda d: d.confidence)

        if best.decision == ResponseDecision.SUPPRESS:
            continue

        action_type = "investigate"
        if best.decision == ResponseDecision.AUTO_REMEDIATE:
            action_type = "contain"
        elif best.decision == ResponseDecision.ESCALATE:
            action_type = "escalate"
            escalations.append(
                {
                    "finding_id": finding.finding_id,
                    "severity": finding.severity,
                    "reason": (f"Low confidence ({best.confidence:.2f})"),
                }
            )

        vendor = finding.vendors_correlated[0] if finding.vendors_correlated else ""
        target = finding.affected_assets[0] if finding.affected_assets else ""

        actions.append(
            ResponseAction(
                action_id=(f"act-{finding.finding_id}"),
                finding_id=finding.finding_id,
                action_type=action_type,
                vendor=vendor,
                target=target,
                description=(f"{action_type}: {finding.description}"),
                decision=best.decision,
                status="pending",
            )
        )

    return {
        "response_actions": actions,
        "escalations": escalations,
        "current_stage": "decide_response",
    }


# ---------------------------------------------------------------
# 5. execute_response
# ---------------------------------------------------------------


async def execute_response(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Execute auto-approved response actions."""
    toolkit = _get_toolkit()
    executed: list[ResponseAction] = []

    for action in state.response_actions:
        if action.decision != ResponseDecision.AUTO_REMEDIATE:
            executed.append(action)
            continue

        exec_start = datetime.now(UTC).isoformat()
        try:
            if action.action_type == "contain":
                result = await toolkit.execute_containment(
                    vendor=action.vendor,
                    target=action.target,
                    action=action.description,
                )
            else:
                result = await toolkit.execute_remediation(
                    vendor=action.vendor,
                    target=action.target,
                    action=action.description,
                )
            action.status = result.get("status", "completed")
            action.result = result
        except Exception as exc:
            action.status = "failed"
            action.error = str(exc)

        action.started_at = exec_start
        action.completed_at = datetime.now(UTC).isoformat()
        executed.append(action)

    return {
        "response_actions": executed,
        "current_stage": "execute_response",
    }


# ---------------------------------------------------------------
# 6. validate_and_learn
# ---------------------------------------------------------------


async def validate_and_learn(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Validate responses and record closed-loop feedback."""
    toolkit = _get_toolkit()
    validations: list[ValidationResult] = []
    improvements: list[ClosedLoopImprovement] = []

    for action in state.response_actions:
        if action.status in ("pending", "skipped"):
            continue

        validated = action.status not in (
            "failed",
            "blocked",
        )
        residual = "low" if validated else "high"

        validations.append(
            ValidationResult(
                action_id=action.action_id,
                validated=validated,
                residual_risk=residual,
                lessons_learned=(
                    f"Action {action.action_type} "
                    f"on {action.vendor} "
                    f"{'succeeded' if validated else 'failed'}"
                ),
                feedback_score=(1.0 if validated else 0.0),
            )
        )

        # Closed-loop feedback
        outcome = "true_positive" if validated else "inconclusive"
        fb = await toolkit.record_feedback(
            alert_id=(action.finding_id if action.finding_id else action.action_id),
            original_decision=action.decision.value,
            actual_outcome=outcome,
            accuracy_delta=(0.02 if validated else -0.05),
        )
        improvements.append(ClosedLoopImprovement(**fb))

    return {
        "validation_results": validations,
        "closed_loop_improvements": improvements,
        "current_stage": "validate_and_learn",
    }


# ---------------------------------------------------------------
# 7. report
# ---------------------------------------------------------------


async def report(
    state: AgenticMDRState,
) -> dict[str, Any]:
    """Generate final MDR report with MTTR tracking."""
    # Calculate MTTR
    duration_ms = 0
    mttr_seconds = 0.0
    if state.session_start:
        duration_ms = int((datetime.now(UTC) - state.session_start).total_seconds() * 1000)
        mttr_seconds = duration_ms / 1000.0

    # LLM-enhanced report
    report_data: dict[str, Any] = {
        "alert_count": state.alert_count,
        "findings_count": len(state.findings),
        "actions_count": len(state.response_actions),
        "validations_count": len(state.validation_results),
        "improvements_count": len(state.closed_loop_improvements),
        "mean_time_to_respond_seconds": mttr_seconds,
        "duration_ms": duration_ms,
        "vendors": state.vendor_sources,
    }

    try:
        rpt_ctx = _json.dumps(
            {
                "alerts": [
                    {
                        "id": a.alert_id,
                        "vendor": a.vendor,
                        "severity": a.severity,
                        "title": a.title,
                    }
                    for a in state.ingested_alerts[:20]
                ],
                "findings": [
                    {
                        "id": f.finding_id,
                        "severity": f.severity,
                        "description": f.description,
                        "vendors": f.vendors_correlated,
                    }
                    for f in state.findings[:20]
                ],
                "actions": [
                    {
                        "id": a.action_id,
                        "type": a.action_type,
                        "status": a.status,
                        "vendor": a.vendor,
                    }
                    for a in state.response_actions[:20]
                ],
                "mttr_seconds": mttr_seconds,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{rpt_ctx}",
            schema=ReportLLMOutput,
        )
        report_data["executive_summary"] = getattr(llm_out, "executive_summary", "")
        report_data["timeline"] = getattr(llm_out, "timeline", [])
        report_data["root_cause"] = getattr(llm_out, "root_cause", "")
        report_data["actions_taken"] = getattr(llm_out, "actions_taken", [])
        report_data["recommendations"] = getattr(llm_out, "recommendations", [])
        report_data["severity_final"] = getattr(llm_out, "severity_final", "")
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")
        report_data["executive_summary"] = (
            f"MDR workflow processed {state.alert_count}"
            f" alerts from {len(state.vendor_sources)}"
            " vendors."
        )

    # Record metrics
    toolkit = _get_toolkit()
    await toolkit.record_metric("mttr_seconds", mttr_seconds)
    await toolkit.record_metric(
        "alerts_processed",
        float(state.alert_count),
    )
    await toolkit.record_metric(
        "findings_count",
        float(len(state.findings)),
    )

    logger.info(
        "agentic_mdr.report",
        mttr_seconds=mttr_seconds,
        duration_ms=duration_ms,
    )

    return {
        "report": report_data,
        "mean_time_to_respond_seconds": mttr_seconds,
        "session_duration_ms": duration_ms,
        "current_stage": "report",
    }


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------


def _confidence_decision(
    confidence: float,
) -> ResponseDecision:
    """Map confidence score to response decision."""
    if confidence >= 0.85:
        return ResponseDecision.AUTO_REMEDIATE
    if confidence >= 0.5:
        return ResponseDecision.HUMAN_APPROVE
    return ResponseDecision.ESCALATE


def _depth_from_severity(
    severity: str,
) -> InvestigationDepth:
    """Map severity to investigation depth."""
    if severity in ("critical",):
        return InvestigationDepth.FORENSIC
    if severity in ("high",):
        return InvestigationDepth.DEEP
    if severity in ("medium",):
        return InvestigationDepth.STANDARD
    return InvestigationDepth.SHALLOW
