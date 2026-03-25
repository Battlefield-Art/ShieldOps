"""Compliance Reporter Agent — Node function implementations."""

from __future__ import annotations

import time
from typing import Any

import structlog
from pydantic import BaseModel, Field

from shieldops.utils.llm import llm_structured

from .models import (
    ComplianceFramework,
    ControlStatus,
    ReporterStage,
)
from .prompts import (
    SYSTEM_CONTROL_ASSESSMENT,
    SYSTEM_EVIDENCE_ANALYSIS,
    SYSTEM_REMEDIATION_PLANNING,
    SYSTEM_REPORT_GENERATION,
)
from .tools import FRAMEWORK_CONTROLS, ComplianceReporterToolkit

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Internal LLM output schemas (not exported)
# ---------------------------------------------------------------------------


class _LLMEvidenceAnalysis(BaseModel):
    """LLM evidence coverage analysis."""

    coverage_assessment: str = Field(description="Evidence coverage summary")
    gaps: list[str] = Field(description="Controls lacking evidence")
    confidence: float = Field(description="Confidence 0-1 in evidence completeness")


class _LLMControlAssessment(BaseModel):
    """LLM control assessment reasoning."""

    critical_findings: list[str] = Field(description="Critical compliance findings")
    risk_level: str = Field(description="Overall risk: critical/high/medium/low")
    assessment_rationale: str = Field(description="Rationale for assessment")


class _LLMReportNarrative(BaseModel):
    """LLM executive summary generation."""

    executive_summary: str = Field(description="Executive summary for stakeholders")
    key_strengths: list[str] = Field(description="Compliance strengths")
    key_risks: list[str] = Field(description="Compliance risks")
    recommendations: list[str] = Field(description="Prioritized recommendations")


class _LLMRemediation(BaseModel):
    """LLM remediation planning."""

    remediation_plan: list[str] = Field(description="Ordered remediation steps")
    estimated_effort: str = Field(description="Effort: low/medium/high")
    quick_wins: list[str] = Field(description="Low-effort high-impact fixes")


# ---------------------------------------------------------------------------
# Node: select_framework
# ---------------------------------------------------------------------------


async def select_framework(
    state: dict[str, Any], toolkit: ComplianceReporterToolkit
) -> dict[str, Any]:
    """Validate selected framework and resolve control set."""
    logger.info("compliance_reporter.node.select_framework")
    framework = state.get("framework", ComplianceFramework.SOC2_TYPE2)
    if isinstance(framework, ComplianceFramework):
        framework = framework.value

    controls = FRAMEWORK_CONTROLS.get(framework, [])
    if not controls:
        return {
            "stage": ReporterStage.COLLECT_EVIDENCE.value,
            "error": f"Unknown framework: {framework}",
            "reasoning_chain": state.get("reasoning_chain", [])
            + [f"Framework '{framework}' not found in control registry"],
            "current_step": 1,
        }

    return {
        "stage": ReporterStage.COLLECT_EVIDENCE.value,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Selected framework '{framework}' with {len(controls)} controls"],
        "current_step": 1,
    }


# ---------------------------------------------------------------------------
# Node: collect_evidence
# ---------------------------------------------------------------------------


async def collect_evidence(
    state: dict[str, Any], toolkit: ComplianceReporterToolkit
) -> dict[str, Any]:
    """Gather evidence artifacts for all controls in the framework."""
    logger.info("compliance_reporter.node.collect_evidence")
    framework = state.get("framework", ComplianceFramework.SOC2_TYPE2)
    if isinstance(framework, ComplianceFramework):
        framework = framework.value

    controls = FRAMEWORK_CONTROLS.get(framework, [])
    evidence_items = await toolkit.collect_evidence(framework, controls)

    # --- LLM enhancement: analyze evidence quality ---
    try:
        evidence_summary = "\n".join(
            f"- {e.control_id}: {e.evidence_type} (verified={e.verified})"
            for e in evidence_items[:30]
        )
        analysis = await llm_structured(
            system_prompt=SYSTEM_EVIDENCE_ANALYSIS,
            user_prompt=(
                f"Framework: {framework}\n"
                f"Controls: {len(controls)}\n"
                f"Evidence items collected: {len(evidence_items)}\n\n"
                f"Evidence details:\n{evidence_summary}"
            ),
            schema=_LLMEvidenceAnalysis,
        )
        if isinstance(analysis, _LLMEvidenceAnalysis):
            logger.info(
                "llm_enhanced",
                agent="compliance_reporter",
                node="collect_evidence",
                confidence=analysis.confidence,
            )
    except Exception:
        logger.debug("llm_fallback", agent="compliance_reporter", node="collect_evidence")

    return {
        "stage": ReporterStage.ASSESS_CONTROLS.value,
        "evidence_items": [e.model_dump() for e in evidence_items],
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Collected {len(evidence_items)} evidence items for {len(controls)} controls"],
        "current_step": 2,
    }


# ---------------------------------------------------------------------------
# Node: assess_controls
# ---------------------------------------------------------------------------


async def assess_controls(
    state: dict[str, Any], toolkit: ComplianceReporterToolkit
) -> dict[str, Any]:
    """Evaluate each control against collected evidence."""
    logger.info("compliance_reporter.node.assess_controls")
    framework = state.get("framework", ComplianceFramework.SOC2_TYPE2)
    if isinstance(framework, ComplianceFramework):
        framework = framework.value

    from .models import EvidenceItem

    raw_evidence = state.get("evidence_items", [])
    evidence = [EvidenceItem(**e) if isinstance(e, dict) else e for e in raw_evidence]

    assessments = await toolkit.assess_controls(framework, evidence)

    # --- LLM enhancement: deeper assessment reasoning ---
    llm_note = ""
    try:
        non_compliant = [a for a in assessments if a.status == ControlStatus.NON_COMPLIANT]
        partial = [a for a in assessments if a.status == ControlStatus.PARTIALLY_COMPLIANT]
        assessment_summary = "\n".join(
            f"- {a.control_id} ({a.control_name}): {a.status.value}, findings={a.findings}"
            for a in assessments[:30]
        )
        result = await llm_structured(
            system_prompt=SYSTEM_CONTROL_ASSESSMENT,
            user_prompt=(
                f"Framework: {framework}\n"
                f"Total controls: {len(assessments)}\n"
                f"Non-compliant: {len(non_compliant)}\n"
                f"Partially compliant: {len(partial)}\n\n"
                f"Assessment details:\n{assessment_summary}"
            ),
            schema=_LLMControlAssessment,
        )
        if isinstance(result, _LLMControlAssessment):
            llm_note = (
                f" | LLM: risk={result.risk_level}, "
                f"critical_findings={len(result.critical_findings)}"
            )
            logger.info(
                "llm_enhanced",
                agent="compliance_reporter",
                node="assess_controls",
                risk_level=result.risk_level,
            )
    except Exception:
        logger.debug("llm_fallback", agent="compliance_reporter", node="assess_controls")

    return {
        "stage": ReporterStage.GENERATE_REPORT.value,
        "control_assessments": [a.model_dump() for a in assessments],
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Assessed {len(assessments)} controls{llm_note}"],
        "current_step": 3,
    }


# ---------------------------------------------------------------------------
# Node: generate_report
# ---------------------------------------------------------------------------


async def generate_report(
    state: dict[str, Any], toolkit: ComplianceReporterToolkit
) -> dict[str, Any]:
    """Compile assessments into a formal compliance report."""
    logger.info("compliance_reporter.node.generate_report")
    framework = state.get("framework", ComplianceFramework.SOC2_TYPE2)
    if isinstance(framework, ComplianceFramework):
        framework = framework.value

    from .models import ControlAssessment

    raw_assessments = state.get("control_assessments", [])
    assessments = [ControlAssessment(**a) if isinstance(a, dict) else a for a in raw_assessments]

    period_start = state.get("period_start", "")
    period_end = state.get("period_end", "")

    report = await toolkit.generate_report(framework, assessments, period_start, period_end)

    # --- LLM enhancement: generate executive narrative ---
    try:
        result = await llm_structured(
            system_prompt=SYSTEM_REPORT_GENERATION,
            user_prompt=(
                f"Framework: {framework}\n"
                f"Period: {period_start} to {period_end}\n"
                f"Score: {report.compliance_score * 100:.1f}%\n"
                f"Total controls: {report.total_controls}\n"
                f"Compliant: {report.compliant_count}\n"
                f"Partially compliant: {report.partially_compliant_count}\n"
                f"Non-compliant: {report.non_compliant_count}\n\n"
                f"Current summary: {report.executive_summary}"
            ),
            schema=_LLMReportNarrative,
        )
        if isinstance(result, _LLMReportNarrative) and result.executive_summary:
            report.executive_summary = result.executive_summary
            logger.info(
                "llm_enhanced",
                agent="compliance_reporter",
                node="generate_report",
                strengths=len(result.key_strengths),
                risks=len(result.key_risks),
            )
    except Exception:
        logger.debug("llm_fallback", agent="compliance_reporter", node="generate_report")

    return {
        "stage": ReporterStage.PACKAGE_ARTIFACTS.value,
        "compliance_report": report.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Report generated: score={report.compliance_score * 100:.1f}%, "
            f"{report.total_controls} controls assessed"
        ],
        "current_step": 4,
    }


# ---------------------------------------------------------------------------
# Node: package_artifacts
# ---------------------------------------------------------------------------


async def package_artifacts(
    state: dict[str, Any], toolkit: ComplianceReporterToolkit
) -> dict[str, Any]:
    """Create evidence package with integrity hashes."""
    logger.info("compliance_reporter.node.package_artifacts")

    from .models import ComplianceReport, EvidenceItem

    raw_report = state.get("compliance_report")
    if raw_report is None:
        return {
            "stage": ReporterStage.DELIVER.value,
            "error": "No report to package",
            "reasoning_chain": state.get("reasoning_chain", [])
            + ["Skipped packaging — no report available"],
            "current_step": 5,
        }

    report = ComplianceReport(**raw_report) if isinstance(raw_report, dict) else raw_report
    raw_evidence = state.get("evidence_items", [])
    evidence = [EvidenceItem(**e) if isinstance(e, dict) else e for e in raw_evidence]

    package = await toolkit.package_artifacts(report, evidence)

    return {
        "stage": ReporterStage.DELIVER.value,
        "artifact_package": package.model_dump(),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Packaged {package.total_artifacts} artifacts "
            f"({package.total_size_mb}MB), hash={package.hash_digest[:16]}..."
        ],
        "current_step": 5,
    }


# ---------------------------------------------------------------------------
# Node: deliver
# ---------------------------------------------------------------------------


async def deliver(state: dict[str, Any], toolkit: ComplianceReporterToolkit) -> dict[str, Any]:
    """Deliver report and evidence package to stakeholders."""
    logger.info("compliance_reporter.node.deliver")

    from .models import ComplianceReport

    raw_report = state.get("compliance_report")
    if raw_report is None:
        return {
            "stage": ReporterStage.DELIVER.value,
            "error": "No report to deliver",
            "reasoning_chain": state.get("reasoning_chain", [])
            + ["Skipped delivery — no report available"],
            "current_step": 6,
            "session_duration_ms": (time.time() - state.get("session_start", time.time())) * 1000,
        }

    report = ComplianceReport(**raw_report) if isinstance(raw_report, dict) else raw_report

    # Default recipients if none provided — derive from context
    default_recipients = ["compliance-team@company.com"]
    delivery_results = await toolkit.deliver_report(report, default_recipients)

    # --- LLM enhancement: generate remediation plan for non-compliant controls ---
    llm_note = ""
    non_compliant = report.non_compliant_count
    if non_compliant > 0:
        try:
            raw_assessments = state.get("control_assessments", [])
            nc_summary = "\n".join(
                f"- {a.get('control_id', 'N/A')}: {a.get('findings', [])}"
                for a in raw_assessments
                if a.get("status") == ControlStatus.NON_COMPLIANT.value
            )
            result = await llm_structured(
                system_prompt=SYSTEM_REMEDIATION_PLANNING,
                user_prompt=(
                    f"Framework: {report.framework}\n"
                    f"Non-compliant controls: {non_compliant}\n\n"
                    f"Findings:\n{nc_summary}"
                ),
                schema=_LLMRemediation,
            )
            if isinstance(result, _LLMRemediation):
                llm_note = (
                    f" | Remediation: effort={result.estimated_effort}, "
                    f"quick_wins={len(result.quick_wins)}"
                )
                logger.info(
                    "llm_enhanced",
                    agent="compliance_reporter",
                    node="deliver",
                    effort=result.estimated_effort,
                )
        except Exception:
            logger.debug("llm_fallback", agent="compliance_reporter", node="deliver")

    session_start = state.get("session_start", time.time())
    duration_ms = (time.time() - session_start) * 1000

    return {
        "stage": ReporterStage.DELIVER.value,
        "delivery_results": [r.model_dump() for r in delivery_results],
        "reasoning_chain": state.get("reasoning_chain", [])
        + [
            f"Delivered to {len(delivery_results)} recipients, "
            f"all successful={all(r.success for r in delivery_results)}{llm_note}"
        ],
        "current_step": 6,
        "session_duration_ms": duration_ms,
    }
