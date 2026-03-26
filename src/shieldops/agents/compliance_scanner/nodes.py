"""Compliance Scanner Agent — Node function implementations."""

from __future__ import annotations

import json
from typing import Any, cast

import structlog

from shieldops.utils.llm import llm_structured

from .models import (
    ComplianceControl,
    ComplianceStage,
    ControlStatus,
    ScanFinding,
)
from .prompts import (
    SYSTEM_EVALUATE,
    SYSTEM_EVIDENCE,
    SYSTEM_REPORT,
    ComplianceReportResult,
    EvidenceGenerationResult,
    FindingEvaluationResult,
)
from .tools import ComplianceScannerToolkit

logger = structlog.get_logger()


async def select_frameworks(
    state: dict[str, Any], toolkit: ComplianceScannerToolkit
) -> dict[str, Any]:
    """Select compliance frameworks to scan."""
    logger.info("compliance_scanner.node.select_frameworks")

    requested = state.get("frameworks", [])
    frameworks = await toolkit.select_frameworks(requested or None)

    return {
        "stage": ComplianceStage.SCAN_CONTROLS.value,
        "frameworks": frameworks,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Selected {len(frameworks)} frameworks: {', '.join(frameworks)}"],
    }


async def scan_controls(state: dict[str, Any], toolkit: ComplianceScannerToolkit) -> dict[str, Any]:
    """Scan compliance controls."""
    logger.info("compliance_scanner.node.scan_controls")

    frameworks = state.get("frameworks", [])
    tenant_id = state.get("tenant_id", "")
    controls = await toolkit.scan_controls(frameworks, tenant_id)
    controls_data = [c.model_dump(mode="json") for c in controls]

    pass_count = sum(1 for c in controls if c.status == ControlStatus.PASS)
    fail_count = sum(1 for c in controls if c.status == ControlStatus.FAIL)

    return {
        "stage": ComplianceStage.EVALUATE_FINDINGS.value,
        "controls": controls_data,
        "total_controls": len(controls),
        "pass_count": pass_count,
        "fail_count": fail_count,
        "compliance_score": toolkit.calculate_compliance_score(controls),
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Scanned {len(controls)} controls: {pass_count} pass, {fail_count} fail"],
    }


async def evaluate_findings(
    state: dict[str, Any], toolkit: ComplianceScannerToolkit
) -> dict[str, Any]:
    """Evaluate compliance findings."""
    logger.info("compliance_scanner.node.evaluate_findings")

    raw_controls = state.get("controls", [])
    controls = [ComplianceControl(**c) for c in raw_controls]
    findings = await toolkit.evaluate_findings(controls)
    findings_data = [f.model_dump() for f in findings]

    reasoning_note = f"Generated {len(findings)} compliance findings"

    if findings:
        try:
            context = json.dumps(
                {
                    "findings": [
                        {
                            "control_id": f.control_id,
                            "finding_type": f.finding_type,
                            "severity": f.severity,
                        }
                        for f in findings[:15]
                    ],
                },
                default=str,
            )
            result = cast(
                FindingEvaluationResult,
                await llm_structured(
                    system_prompt=SYSTEM_EVALUATE,
                    user_prompt=f"Finding evaluation context:\n{context}",
                    schema=FindingEvaluationResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="compliance_scanner", node="evaluate")

    return {
        "stage": ComplianceStage.TRACK_REMEDIATION.value,
        "findings": findings_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def track_remediation(
    state: dict[str, Any], toolkit: ComplianceScannerToolkit
) -> dict[str, Any]:
    """Track remediation of findings."""
    logger.info("compliance_scanner.node.track_remediation")

    raw_findings = state.get("findings", [])
    findings = [ScanFinding(**f) for f in raw_findings]
    trackers = await toolkit.track_remediation(findings)
    trackers_data = [t.model_dump(mode="json") for t in trackers]

    auto_count = sum(1 for t in trackers if t.status == "auto_remediated")
    return {
        "stage": ComplianceStage.GENERATE_EVIDENCE.value,
        "remediations": trackers_data,
        "reasoning_chain": state.get("reasoning_chain", [])
        + [f"Tracking {len(trackers)} remediations ({auto_count} auto-remediated)"],
    }


async def generate_evidence(
    state: dict[str, Any], toolkit: ComplianceScannerToolkit
) -> dict[str, Any]:
    """Generate compliance evidence."""
    logger.info("compliance_scanner.node.generate_evidence")

    raw_controls = state.get("controls", [])
    controls = [ComplianceControl(**c) for c in raw_controls]
    artifacts = await toolkit.generate_evidence(controls)
    artifacts_data = [a.model_dump(mode="json") for a in artifacts]

    reasoning_note = f"Collected {len(artifacts)} evidence artifacts"

    if controls:
        try:
            context = json.dumps(
                {
                    "total_controls": len(controls),
                    "evidence_collected": len(artifacts),
                    "controls_without_evidence": sum(
                        1 for c in controls if c.status != ControlStatus.PASS
                    ),
                },
                default=str,
            )
            result = cast(
                EvidenceGenerationResult,
                await llm_structured(
                    system_prompt=SYSTEM_EVIDENCE,
                    user_prompt=f"Evidence context:\n{context}",
                    schema=EvidenceGenerationResult,
                ),
            )
            reasoning_note = f"{result.summary}. {reasoning_note}"
        except Exception:
            logger.debug("llm_fallback", agent="compliance_scanner", node="evidence")

    return {
        "stage": ComplianceStage.REPORT.value,
        "evidence": artifacts_data,
        "reasoning_chain": state.get("reasoning_chain", []) + [reasoning_note],
    }


async def generate_report(
    state: dict[str, Any], toolkit: ComplianceScannerToolkit
) -> dict[str, Any]:
    """Generate compliance report."""
    logger.info("compliance_scanner.node.report")

    total = state.get("total_controls", 0)
    pass_count = state.get("pass_count", 0)
    fail_count = state.get("fail_count", 0)
    score = state.get("compliance_score", 0.0)
    summary = (
        f"Compliance score: {score}% — {total} controls scanned, "
        f"{pass_count} pass, {fail_count} fail"
    )

    try:
        context = json.dumps(
            {
                "total_controls": total,
                "pass_count": pass_count,
                "fail_count": fail_count,
                "compliance_score": score,
                "frameworks": state.get("frameworks", []),
                "findings_count": len(state.get("findings", [])),
                "evidence_count": len(state.get("evidence", [])),
            },
            default=str,
        )
        result = cast(
            ComplianceReportResult,
            await llm_structured(
                system_prompt=SYSTEM_REPORT,
                user_prompt=f"Compliance report context:\n{context}",
                schema=ComplianceReportResult,
            ),
        )
        summary = result.executive_summary
    except Exception:
        logger.debug("llm_fallback", agent="compliance_scanner", node="report")

    return {
        "stage": ComplianceStage.REPORT.value,
        "summary": summary,
        "reasoning_chain": state.get("reasoning_chain", []) + [summary],
    }
