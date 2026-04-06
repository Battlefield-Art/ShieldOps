"""Compliance Auditor Agent — Node function implementations."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    AuditStage,
    ComplianceFinding,
    ComplianceFramework,
    ControlAssessment,
    EvidenceItem,
)
from .tools import ComplianceAuditorToolkit

logger = structlog.get_logger()


class _LLMGapAnalysis(BaseModel):
    """LLM-generated compliance gap analysis."""

    critical_gaps: list[str] = Field(description="Most critical compliance gaps requiring action")
    remediation_priorities: list[str] = Field(description="Ordered list of remediation priorities")
    risk_summary: str = Field(description="Overall risk summary from the gap analysis")
    estimated_remediation_effort: str = Field(
        description="Estimated effort to remediate (low/medium/high)"
    )


async def scan_infrastructure(
    state: dict[str, Any], toolkit: ComplianceAuditorToolkit
) -> dict[str, Any]:
    """Scan controls for each requested compliance framework.

    Also runs AWS Config auditing, security group evaluation, and
    public access detection to gather comprehensive infrastructure data.
    """
    logger.info("compliance_auditor.node.scan")
    frameworks = state.get("frameworks", [])

    all_controls: list[dict[str, Any]] = []
    for fw in frameworks:
        fw_value = fw.value if isinstance(fw, ComplianceFramework) else fw
        scanned = await toolkit.scan_controls(fw_value)
        all_controls.extend(scanned)

    assessments = [ControlAssessment(**c).model_dump() for c in all_controls]

    # Run additional AWS infrastructure scans
    aws_findings = await toolkit.audit_aws_config()
    sg_findings = await toolkit.evaluate_security_groups()
    public_access_findings = await toolkit.detect_public_access()

    # Enrich findings with LLM-powered remediation suggestions
    aws_findings_enriched = await toolkit.generate_remediation_suggestions(aws_findings)

    # Generate structured compliance findings
    fw_keys = [fw.value if isinstance(fw, ComplianceFramework) else fw for fw in frameworks]
    cloudtrail_placeholder: dict[str, Any] = {}  # Will be populated in next node
    compliance_findings = toolkit.generate_compliance_findings(
        aws_findings=aws_findings_enriched,
        security_group_findings=sg_findings,
        cloudtrail_events=cloudtrail_placeholder,
        public_access_findings=public_access_findings,
        frameworks=fw_keys,
    )

    scan_summary = (
        f"Scanned {len(assessments)} controls across {len(frameworks)} frameworks, "
        f"{len(aws_findings)} AWS config findings, {len(sg_findings)} security group findings, "
        f"{len(public_access_findings)} public access findings"
    )

    return {
        "stage": AuditStage.CLOUDTRAIL_ANALYSIS.value,
        "controls_assessed": assessments,
        "findings": [ComplianceFinding(**f).model_dump() for f in compliance_findings],
        "security_group_findings": [f for f in sg_findings],
        "reasoning_chain": state.get("reasoning_chain", []) + [scan_summary],
    }


async def analyze_cloudtrail(
    state: dict[str, Any], toolkit: ComplianceAuditorToolkit
) -> dict[str, Any]:
    """Analyze CloudTrail events for compliance-relevant activity.

    Detects unauthorized API calls, root account usage, and IAM changes.
    Generates additional compliance findings from CloudTrail data.
    """
    logger.info("compliance_auditor.node.analyze_cloudtrail")
    frameworks = state.get("frameworks", [])

    cloudtrail_events = await toolkit.analyze_cloudtrail_events()

    # Generate compliance findings from CloudTrail events
    fw_keys = [fw.value if isinstance(fw, ComplianceFramework) else fw for fw in frameworks]
    ct_findings = toolkit.generate_compliance_findings(
        aws_findings=[],
        security_group_findings=[],
        cloudtrail_events=cloudtrail_events,
        public_access_findings=[],
        frameworks=fw_keys,
    )

    existing_findings = state.get("findings", [])
    all_findings = existing_findings + [ComplianceFinding(**f).model_dump() for f in ct_findings]

    # Evaluate OPA policy against all findings
    all_findings_for_opa = [
        {"status": f.get("status", ""), "risk_level": f.get("severity", ""), **f}
        for f in all_findings
    ]
    policy_result = await toolkit.evaluate_opa_policy(all_findings_for_opa)

    ct_summary = (
        f"CloudTrail: {cloudtrail_events.get('unauthorized_count', 0)} unauthorized, "
        f"{cloudtrail_events.get('root_usage_count', 0)} root usage, "
        f"{cloudtrail_events.get('iam_change_count', 0)} IAM changes. "
        f"OPA decision: {policy_result.get('decision', 'unknown')}"
    )

    return {
        "stage": AuditStage.COLLECT_EVIDENCE.value,
        "findings": all_findings,
        "cloudtrail_events": [
            {"event_id": e.get("event_id", ""), "event_name": e.get("event_name", "")}
            for events_list in [
                cloudtrail_events.get("unauthorized_events", []),
                cloudtrail_events.get("root_account_events", []),
                cloudtrail_events.get("iam_change_events", []),
            ]
            for e in events_list
        ],
        "policy_decision": policy_result.get("decision", ""),
        "policy_details": policy_result,
        "reasoning_chain": state.get("reasoning_chain", []) + [ct_summary],
    }


async def collect_evidence(
    state: dict[str, Any], toolkit: ComplianceAuditorToolkit
) -> dict[str, Any]:
    """Gather evidence for each assessed control."""
    logger.info("compliance_auditor.node.collect_evidence")
    controls = state.get("controls_assessed", [])

    evidence_items: list[dict[str, Any]] = []
    updated_controls: list[dict[str, Any]] = []

    for ctrl in controls:
        control_id = ctrl.get("control_id", "")
        raw_evidence = await toolkit.collect_evidence(control_id)
        ev_models = [EvidenceItem(**e).model_dump() for e in raw_evidence]
        evidence_items.extend(ev_models)

        # Re-assess control with collected evidence
        assessed = toolkit.assess_control(ctrl, raw_evidence)
        updated_controls.append(assessed)

    return {
        "stage": AuditStage.ANALYZE_GAPS.value,
        "controls_assessed": updated_controls,
        "evidence_collected": evidence_items,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(evidence_items)} evidence items for {len(controls)} controls"],
    }


async def analyze_gaps(state: dict[str, Any], toolkit: ComplianceAuditorToolkit) -> dict[str, Any]:
    """Identify non-compliant controls and perform gap analysis."""
    logger.info("compliance_auditor.node.analyze_gaps")
    controls = state.get("controls_assessed", [])

    gaps_found = 0
    for ctrl in controls:
        gaps_found += len(ctrl.get("gaps", []))

    non_compliant = [c for c in controls if c.get("status") == "non_compliant"]
    partial = [c for c in controls if c.get("status") == "partial"]

    # --- LLM enhancement: deeper gap analysis reasoning ---
    llm_analysis_text = ""
    try:
        controls_summary = "\n".join(
            f"- {c.get('control_id', 'N/A')} [{c.get('framework', '')}]: "
            f"status={c.get('status', 'unknown')}, gaps={c.get('gaps', [])}"
            for c in controls[:30]  # cap to avoid token overflow
        )
        analysis = await llm_structured(
            system_prompt=(
                "You are a compliance auditor specializing in SOC2, ISO27001, HIPAA, "
                "PCI-DSS, and GDPR frameworks. Analyze the control assessment results "
                "and provide prioritized remediation guidance. Focus on critical gaps "
                "that pose the highest regulatory risk."
            ),
            user_prompt=(
                f"Total controls assessed: {len(controls)}\n"
                f"Non-compliant: {len(non_compliant)}\n"
                f"Partial: {len(partial)}\n"
                f"Total gaps: {gaps_found}\n\n"
                f"Control details:\n{controls_summary}"
            ),
            schema=_LLMGapAnalysis,
        )
        if isinstance(analysis, _LLMGapAnalysis):
            llm_analysis_text = (
                f"LLM risk summary: {analysis.risk_summary}. "
                f"Effort: {analysis.estimated_remediation_effort}. "
                f"Critical gaps: {len(analysis.critical_gaps)}."
            )
            logger.info(
                "llm_enhanced",
                agent="compliance_auditor",
                node="analyze_gaps",
                critical_gaps=len(analysis.critical_gaps),
                effort=analysis.estimated_remediation_effort,
            )
    except Exception:
        logger.debug("llm_fallback", agent="compliance_auditor", node="analyze_gaps")

    gap_summary = (
        f"Gap analysis complete: {gaps_found} gaps, "
        f"{len(non_compliant)} non-compliant, {len(partial)} partial"
    )
    if llm_analysis_text:
        gap_summary += f" | {llm_analysis_text}"

    return {
        "stage": AuditStage.GENERATE_REPORT.value,
        "gaps_found": gaps_found,
        "reasoning_chain": state.get("reasoning_chain", []) + [gap_summary],
    }


async def generate_report(
    state: dict[str, Any], toolkit: ComplianceAuditorToolkit
) -> dict[str, Any]:
    """Produce compliance report with recommendations."""
    logger.info("compliance_auditor.node.generate_report")
    controls = state.get("controls_assessed", [])

    report = toolkit.generate_audit_report(controls)
    compliance_score = report.get("compliance_score", 0.0)

    return {
        "stage": AuditStage.GENERATE_REPORT.value,
        "report": report,
        "compliance_score": compliance_score,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: score={compliance_score}, "
            f"{report.get('total_controls', 0)} controls assessed"
        ],
    }
