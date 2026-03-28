"""Node implementations for the Compliance Workflow Agent."""

from __future__ import annotations

import json as _json
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.compliance_workflow.models import (
    ComplianceControl,
    ComplianceStage,
    ComplianceWorkflowState,
    ControlStatus,
    EvidenceItem,
    GapFinding,
)
from shieldops.agents.compliance_workflow.prompts import (
    SYSTEM_COLLECT_EVIDENCE,
    SYSTEM_IDENTIFY_CONTROLS,
    SYSTEM_IDENTIFY_GAPS,
    SYSTEM_REPORT,
    SYSTEM_TEST_CONTROLS,
    ControlIdentificationOutput,
    ControlTestOutput,
    GapAnalysisOutput,
    ReportOutput,
)
from shieldops.agents.compliance_workflow.tools import (
    ComplianceWorkflowToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: ComplianceWorkflowToolkit | None = None


def set_toolkit(toolkit: ComplianceWorkflowToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> ComplianceWorkflowToolkit:
    if _toolkit is None:
        return ComplianceWorkflowToolkit()
    return _toolkit


# ------------------------------------------------------------------
# Node: identify_controls
# ------------------------------------------------------------------


async def identify_controls(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Identify applicable controls for the target framework."""
    start = time.time()
    toolkit = _get_toolkit()

    controls = await toolkit.identify_controls(
        framework=state.framework.value,
        tenant_id=state.tenant_id,
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "framework": state.framework.value,
                "tenant_id": state.tenant_id,
                "heuristic_controls": [c.model_dump() for c in controls],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_CONTROLS,
            user_prompt=(f"Identify controls for:\n{context}"),
            schema=ControlIdentificationOutput,
        )
        if hasattr(llm_result, "controls") and llm_result.controls:
            controls = [
                ComplianceControl(
                    id=c.get("id", f"ctrl-{uuid4().hex[:8]}"),
                    name=c.get("name", ""),
                    category=c.get("category", ""),
                    description=c.get("description", ""),
                    framework=state.framework,
                )
                for c in llm_result.controls
            ]
        reasoning = getattr(llm_result, "reasoning", "")
        logger.info("llm_enhanced", node="identify_controls")
    except Exception:
        reasoning = f"Identified {len(controls)} control(s) via heuristic"
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_controls",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "controls": controls,
        "stage": ComplianceStage.COLLECT_EVIDENCE,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"identify_controls: {reasoning} ({elapsed}ms)"),
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
    }


# ------------------------------------------------------------------
# Node: collect_evidence
# ------------------------------------------------------------------


async def collect_evidence(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Collect evidence for all identified controls."""
    start = time.time()
    toolkit = _get_toolkit()
    all_evidence: list[EvidenceItem] = []

    for ctrl in state.controls:
        items = await toolkit.collect_evidence(ctrl)
        all_evidence.extend(items)

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "framework": state.framework.value,
                "controls": [c.model_dump() for c in state.controls],
                "evidence_count": len(all_evidence),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_COLLECT_EVIDENCE,
            user_prompt=(f"Plan evidence collection:\n{context}"),
            schema=ControlIdentificationOutput,
        )
        reasoning = getattr(
            llm_result,
            "coverage_notes",
            f"Collected {len(all_evidence)} evidence items",
        )
        logger.info("llm_enhanced", node="collect_evidence")
    except Exception:
        reasoning = f"Collected {len(all_evidence)} evidence item(s)"
        logger.debug(
            "llm_enhancement_skipped",
            node="collect_evidence",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "evidence_items": all_evidence,
        "stage": ComplianceStage.TEST_CONTROLS,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"collect_evidence: {reasoning} ({elapsed}ms)"),
        ],
    }


# ------------------------------------------------------------------
# Node: test_controls
# ------------------------------------------------------------------


async def test_controls(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Test each control against collected evidence."""
    start = time.time()
    toolkit = _get_toolkit()
    updated_controls: list[ComplianceControl] = []

    # Build evidence lookup by control_id
    evidence_map: dict[str, list[EvidenceItem]] = {}
    for ev in state.evidence_items:
        evidence_map.setdefault(ev.control_id, []).append(ev)

    for ctrl in state.controls:
        ctrl_evidence = evidence_map.get(ctrl.id, [])
        status = await toolkit.test_control(
            ctrl,
            ctrl_evidence,
        )
        updated_controls.append(
            ctrl.model_copy(update={"status": status}),
        )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "controls": [c.model_dump() for c in updated_controls],
                "evidence_count": len(state.evidence_items),
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_TEST_CONTROLS,
            user_prompt=f"Assess control tests:\n{context}",
            schema=ControlTestOutput,
        )
        reasoning = getattr(
            llm_result,
            "overall_assessment",
            "",
        )
        logger.info("llm_enhanced", node="test_controls")
    except Exception:
        passing = sum(1 for c in updated_controls if c.status == ControlStatus.PASSING)
        reasoning = f"{passing}/{len(updated_controls)} controls passing"
        logger.debug(
            "llm_enhancement_skipped",
            node="test_controls",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "controls": updated_controls,
        "stage": ComplianceStage.IDENTIFY_GAPS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"test_controls: {reasoning} ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: identify_gaps
# ------------------------------------------------------------------


async def identify_gaps(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Identify compliance gaps from test results."""
    start = time.time()
    toolkit = _get_toolkit()

    gaps = await toolkit.identify_gaps(state.controls)

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "controls": [c.model_dump() for c in state.controls],
                "heuristic_gaps": [g.model_dump() for g in gaps],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_GAPS,
            user_prompt=f"Analyze gaps:\n{context}",
            schema=GapAnalysisOutput,
        )
        if hasattr(llm_result, "gaps") and llm_result.gaps:
            gaps = [
                GapFinding(
                    id=g.get(
                        "id",
                        f"gap-{uuid4().hex[:8]}",
                    ),
                    control_id=g.get("control_id", ""),
                    severity=g.get("severity", "medium"),
                    description=g.get("description", ""),
                )
                for g in llm_result.gaps
            ]
        reasoning = getattr(
            llm_result,
            "risk_summary",
            f"Found {len(gaps)} gap(s)",
        )
        logger.info("llm_enhanced", node="identify_gaps")
    except Exception:
        reasoning = f"Found {len(gaps)} gap(s) via heuristic"
        logger.debug(
            "llm_enhancement_skipped",
            node="identify_gaps",
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "gaps": gaps,
        "stage": ComplianceStage.REMEDIATE,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_gaps: {reasoning} ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: remediate
# ------------------------------------------------------------------


async def remediate(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Generate remediation plans for identified gaps."""
    start = time.time()
    toolkit = _get_toolkit()
    remediation_items: list[dict[str, str]] = []

    for gap in state.gaps:
        plan = await toolkit.generate_remediation(gap)
        remediation_items.append(plan)

    elapsed = int((time.time() - start) * 1000)
    return {
        "remediation_items": remediation_items,
        "stage": ComplianceStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"remediate: generated {len(remediation_items)} plan(s) ({elapsed}ms)"),
        ],
    }


# ------------------------------------------------------------------
# Node: report
# ------------------------------------------------------------------


async def report(
    state: ComplianceWorkflowState,
) -> dict[str, Any]:
    """Generate the final compliance audit report."""
    start = time.time()
    total_elapsed = int(
        (time.time() - state.session_start) * 1000,
    )

    total = len(state.controls)
    passing = sum(1 for c in state.controls if c.status == ControlStatus.PASSING)
    score = (passing / total * 100.0) if total else 0.0

    summary = (
        f"Framework {state.framework.value}: "
        f"{total} control(s), {passing} passing "
        f"({score:.0f}%), {len(state.gaps)} gap(s)"
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "framework": state.framework.value,
                "total_controls": total,
                "passing": passing,
                "score": score,
                "gaps": [g.model_dump() for g in state.gaps],
                "remediation_items": state.remediation_items,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate compliance report:\n{context}"),
            schema=ReportOutput,
        )
        llm_summary = getattr(
            llm_result,
            "executive_summary",
            "",
        )
        if llm_summary:
            summary = llm_summary
        llm_score = getattr(
            llm_result,
            "overall_score",
            None,
        )
        if llm_score is not None:
            score = float(llm_score)
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    return {
        "overall_score": score,
        "stage": ComplianceStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"report: {summary} ({elapsed}ms, total {total_elapsed}ms)"),
        ],
    }
