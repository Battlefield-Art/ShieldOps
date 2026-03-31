"""Node implementations for the Data Privacy Scanner
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.data_privacy_scanner.models import (
    DataPrivacyScannerState,
    DPSStage,
    ReasoningStep,
)
from shieldops.agents.data_privacy_scanner.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_FLOWS,
    SYSTEM_PII,
    SYSTEM_REPORT,
    DataClassificationOutput,
    DataFlowOutput,
    PIIDetectionOutput,
    PrivacyReportOutput,
)
from shieldops.agents.data_privacy_scanner.tools import (
    DataPrivacyScannerToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: DataPrivacyScannerToolkit | None = None


def set_toolkit(
    toolkit: DataPrivacyScannerToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> DataPrivacyScannerToolkit:
    if _toolkit is None:
        return DataPrivacyScannerToolkit()
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
# Node: scan_datastores
# ------------------------------------------------------------------


async def scan_datastores(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Discover and enumerate datastores in scope."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    datastores = await toolkit.scan_datastores(
        targets=state.target_datastores,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "scan_datastores",
        (f"Scanning {len(state.target_datastores)} target datastores"),
        f"Discovered {len(datastores)} datastores",
        start,
        "datastore_client",
    )

    return {
        "datastores": datastores,
        "total_datastores": len(datastores),
        "stage": DPSStage.SCAN_DATASTORES,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "scan_datastores",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: classify_data
# ------------------------------------------------------------------


async def classify_data(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Classify data fields by sensitivity category."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_data(
        datastores=state.datastores,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "datastore_count": len(state.datastores),
                "datastores_sample": state.datastores[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=(f"Classify data fields:\n{ctx}"),
            schema=DataClassificationOutput,
        )
        if llm_out.classifications:  # type: ignore[union-attr]
            classifications = [
                *classifications,
                *llm_out.classifications,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="classify_data",
            count=len(llm_out.classifications),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_data",
        )

    step = _step(
        state.reasoning_chain,
        "classify_data",
        f"Classifying {len(state.datastores)} datastores",
        f"Produced {len(classifications)} classifications",
        start,
        "classifier",
    )

    return {
        "classifications": classifications,
        "stage": DPSStage.CLASSIFY_DATA,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_data",
    }


# ------------------------------------------------------------------
# Node: detect_pii
# ------------------------------------------------------------------


async def detect_pii(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Detect PII/PHI/PCI data with high precision."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    pii_findings = await toolkit.detect_pii(
        datastores=state.datastores,
        classifications=state.classifications,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "classifications_sample": (state.classifications[:5]),
                "datastores_sample": state.datastores[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_PII,
            user_prompt=f"Detect PII:\n{ctx}",
            schema=PIIDetectionOutput,
        )
        if llm_out.findings:  # type: ignore[union-attr]
            pii_findings = [
                *pii_findings,
                *llm_out.findings,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="detect_pii",
            total=llm_out.total_pii_records,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="detect_pii",
        )

    _pii = sum(1 for f in pii_findings if f.get("category") == "pii")
    _phi = sum(1 for f in pii_findings if f.get("category") == "phi")
    _pci = sum(1 for f in pii_findings if f.get("category") == "pci")

    step = _step(
        state.reasoning_chain,
        "detect_pii",
        (f"Detecting PII across {len(state.datastores)} datastores"),
        (f"Found {len(pii_findings)} findings: {_pii} PII, {_phi} PHI, {_pci} PCI"),
        start,
        "pii_detector",
    )

    return {
        "pii_findings": pii_findings,
        "pii_count": _pii,
        "phi_count": _phi,
        "pci_count": _pci,
        "stage": DPSStage.DETECT_PII,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "detect_pii",
    }


# ------------------------------------------------------------------
# Node: map_flows
# ------------------------------------------------------------------


async def map_flows(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Map data flows between systems containing
    sensitive data."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    data_flows = await toolkit.map_data_flows(
        datastores=state.datastores,
        pii_findings=state.pii_findings,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "datastores_sample": state.datastores[:5],
                "pii_findings_sample": state.pii_findings[:5],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_FLOWS,
            user_prompt=f"Map data flows:\n{ctx}",
            schema=DataFlowOutput,
        )
        if llm_out.flows:  # type: ignore[union-attr]
            data_flows = [
                *data_flows,
                *llm_out.flows,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="map_flows",
            cross_border=llm_out.cross_border_flows,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="map_flows",
        )

    step = _step(
        state.reasoning_chain,
        "map_flows",
        (f"Mapping flows for {len(state.pii_findings)} PII findings"),
        f"Mapped {len(data_flows)} data flows",
        start,
        "flow_mapper",
    )

    return {
        "data_flows": data_flows,
        "stage": DPSStage.MAP_FLOWS,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "map_flows",
    }


# ------------------------------------------------------------------
# Node: assess_compliance
# ------------------------------------------------------------------


async def assess_compliance(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Assess compliance against configured privacy
    regimes."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    regimes = [r.value for r in state.regimes]
    assessments = await toolkit.assess_compliance(
        pii_findings=state.pii_findings,
        data_flows=state.data_flows,
        regimes=regimes,
    )

    _scores = [a.get("score", 0.0) for a in assessments]
    _avg_score = sum(_scores) / max(len(_scores), 1)

    step = _step(
        state.reasoning_chain,
        "assess_compliance",
        (f"Assessing compliance against {len(regimes)} regimes"),
        (f"Produced {len(assessments)} assessments, avg score={_avg_score:.1f}"),
        start,
        "compliance_engine",
    )

    return {
        "compliance_assessments": assessments,
        "compliance_score": _avg_score,
        "stage": DPSStage.ASSESS_COMPLIANCE,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "assess_compliance",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: DataPrivacyScannerState,
) -> dict[str, Any]:
    """Generate the final data privacy scan report."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    report: dict[str, Any] = {
        "scan_name": state.scan_name,
        "total_datastores": state.total_datastores,
        "pii_count": state.pii_count,
        "phi_count": state.phi_count,
        "pci_count": state.pci_count,
        "compliance_score": state.compliance_score,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "scan_name": state.scan_name,
                "total_datastores": state.total_datastores,
                "pii_count": state.pii_count,
                "phi_count": state.phi_count,
                "pci_count": state.pci_count,
                "pii_findings_sample": state.pii_findings[:5],
                "data_flows_sample": state.data_flows[:5],
                "compliance_assessments": (state.compliance_assessments[:5]),
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=(f"Generate privacy report:\n{ctx}"),
            schema=PrivacyReportOutput,
        )
        if isinstance(llm_out, PrivacyReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "critical_findings": (llm_out.critical_findings),
                    "compliance_gaps": llm_out.compliance_gaps,
                    "recommendations": llm_out.recommendations,
                    "overall_score": llm_out.overall_score,
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

    # Record metrics
    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    await toolkit.record_metric(
        scan_id=state.request_id,
        outcome={
            "total_datastores": state.total_datastores,
            "pii_count": state.pii_count,
            "phi_count": state.phi_count,
            "pci_count": state.pci_count,
            "compliance_score": state.compliance_score,
            "duration_ms": duration_ms,
        },
    )

    step = _step(
        state.reasoning_chain,
        "generate_report",
        (f"Reporting on {state.total_datastores} datastores"),
        (f"Report generated, score={state.compliance_score:.1f}"),
        start,
        "report_generator",
    )

    return {
        "report": report,
        "session_duration_ms": duration_ms,
        "stage": DPSStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
