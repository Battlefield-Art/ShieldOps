"""Node implementations for the Privacy Rights Automator
Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from shieldops.agents.privacy_rights_automator.models import (
    PRAStage,
    PrivacyRightsAutomatorState,
    ReasoningStep,
)
from shieldops.agents.privacy_rights_automator.prompts import (
    SYSTEM_CLASSIFY,
    SYSTEM_LOCATE,
    SYSTEM_REPORT,
    SYSTEM_VALIDATE,
    ActionValidationOutput,
    ComplianceReportOutput,
    DataLocationOutput,
    PIIClassificationOutput,
)
from shieldops.agents.privacy_rights_automator.tools import (
    PrivacyRightsAutomatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: PrivacyRightsAutomatorToolkit | None = None


def set_toolkit(
    toolkit: PrivacyRightsAutomatorToolkit,
) -> None:
    """Set the module-level toolkit instance."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> PrivacyRightsAutomatorToolkit:
    if _toolkit is None:
        return PrivacyRightsAutomatorToolkit()
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
# Node: receive_request
# ------------------------------------------------------------------


async def receive_request(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Intake and validate a data subject rights
    request."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    details = await toolkit.receive_request(
        subject_email=state.subject_email,
        request_type=state.request_type.value,
        regulation=state.regulation.value,
        scope=state.scope,
    )

    step = _step(
        state.reasoning_chain,
        "receive_request",
        (f"Subject: {state.subject_email}, type={state.request_type}"),
        "Request received and validated",
        start,
        "request_intake",
    )

    return {
        "request_details": details,
        "stage": PRAStage.RECEIVE_REQUEST,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "receive_request",
        "session_start": start,
    }


# ------------------------------------------------------------------
# Node: locate_data
# ------------------------------------------------------------------


async def locate_data(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Locate all personal data belonging to the data
    subject across systems."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    locations = await toolkit.locate_data(
        subject_email=state.subject_email,
        systems=state.systems,
        scope=state.scope,
    )

    data_locations: list[dict[str, Any]] = list(locations)

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "subject": state.subject_email,
                "systems": state.systems,
                "scope": state.scope,
                "regulation": state.regulation.value,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_LOCATE,
            user_prompt=f"Locate subject data:\n{ctx}",
            schema=DataLocationOutput,
        )
        if llm_out.locations:  # type: ignore[union-attr]
            data_locations = [
                *data_locations,
                *llm_out.locations,  # type: ignore[union-attr]
            ]
        logger.info(
            "llm_enhanced",
            node="locate_data",
            count=len(llm_out.locations),  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="locate_data",
        )

    step = _step(
        state.reasoning_chain,
        "locate_data",
        f"Searching {len(state.systems)} systems",
        f"Found {len(data_locations)} data locations",
        start,
        "data_catalog",
    )

    return {
        "data_locations": data_locations,
        "stage": PRAStage.LOCATE_DATA,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "locate_data",
    }


# ------------------------------------------------------------------
# Node: classify_pii
# ------------------------------------------------------------------


async def classify_pii(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Classify discovered data by PII category and
    sensitivity level."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    classifications = await toolkit.classify_pii(
        locations=state.data_locations,
        regulation=state.regulation.value,
    )

    # LLM enhancement
    try:
        ctx = _json.dumps(
            {
                "location_count": len(state.data_locations),
                "location_sample": state.data_locations[:5],
                "regulation": state.regulation.value,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_CLASSIFY,
            user_prompt=f"Classify PII:\n{ctx}",
            schema=PIIClassificationOutput,
        )
        if llm_out.classifications:  # type: ignore[union-attr]
            _rand = random.randint(1000, 9999)  # noqa: S311
            classifications.append(
                {
                    "classification_id": f"llm-{_rand}",
                    "high_risk_fields": (
                        llm_out.high_risk_fields  # type: ignore[union-attr]
                    ),
                    "retention_risks": (
                        llm_out.retention_risks  # type: ignore[union-attr]
                    ),
                    "summary": llm_out.summary,  # type: ignore[union-attr]
                }
            )
        logger.info(
            "llm_enhanced",
            node="classify_pii",
            count=len(
                llm_out.classifications  # type: ignore[union-attr]
            ),
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="classify_pii",
        )

    step = _step(
        state.reasoning_chain,
        "classify_pii",
        (f"Classifying {len(state.data_locations)} locations"),
        f"Produced {len(classifications)} classifications",
        start,
        "pii_classifier",
    )

    return {
        "classifications": classifications,
        "stage": PRAStage.CLASSIFY_PII,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "classify_pii",
    }


# ------------------------------------------------------------------
# Node: process_action
# ------------------------------------------------------------------


async def process_action(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Execute the requested privacy action across all
    identified data locations."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    results: list[dict[str, Any]] = []
    total_records = 0

    # Validate plan via LLM before execution
    try:
        ctx = _json.dumps(
            {
                "request_type": state.request_type.value,
                "regulation": state.regulation.value,
                "locations": state.data_locations[:10],
                "classifications": state.classifications[:10],
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_VALIDATE,
            user_prompt=f"Validate action plan:\n{ctx}",
            schema=ActionValidationOutput,
        )
        logger.info(
            "llm_enhanced",
            node="process_action",
            validated=llm_out.validated,  # type: ignore[union-attr]
        )
    except Exception:
        logger.debug(
            "llm_enhancement_skipped",
            node="process_action",
        )

    action_results = await toolkit.process_action(
        request_type=state.request_type.value,
        locations=state.data_locations,
        classifications=state.classifications,
    )

    for rec in action_results:
        results.append(rec)
        total_records += rec.get("records_affected", 0)

    step = _step(
        state.reasoning_chain,
        "process_action",
        (f"Processing {state.request_type.value} across {len(state.data_locations)} locations"),
        (f"{len(results)} actions, {total_records} records"),
        start,
        "action_processor",
    )

    return {
        "action_results": results,
        "total_records": total_records,
        "systems_processed": len(results),
        "stage": PRAStage.PROCESS_ACTION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "process_action",
    }


# ------------------------------------------------------------------
# Node: verify_completion
# ------------------------------------------------------------------


async def verify_completion(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Verify that all privacy actions completed
    successfully."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    verification = await toolkit.verify_completion(
        action_results=state.action_results,
        request_type=state.request_type.value,
    )

    fulfilled = verification.get("all_systems_cleared", False) and verification.get(
        "compliance_confirmed", False
    )

    step = _step(
        state.reasoning_chain,
        "verify_completion",
        (f"Verifying {len(state.action_results)} actions"),
        ("Fulfilled" if fulfilled else "Incomplete — follow-up required"),
        start,
        "verification_engine",
    )

    return {
        "verification": verification,
        "request_fulfilled": fulfilled,
        "stage": PRAStage.VERIFY_COMPLETION,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "verify_completion",
    }


# ------------------------------------------------------------------
# Node: generate_report
# ------------------------------------------------------------------


async def generate_report(
    state: PrivacyRightsAutomatorState,
) -> dict[str, Any]:
    """Generate the final compliance report for the
    data subject request."""
    start = datetime.now(UTC)
    toolkit = _get_toolkit()

    # Compute compliance score
    if state.request_fulfilled and state.systems_processed > 0:
        compliance = min(
            1.0,
            0.6 + (state.systems_processed * 0.05),
        )
    elif state.systems_processed > 0:
        compliance = min(0.5, state.systems_processed * 0.1)
    else:
        compliance = 0.1

    report: dict[str, Any] = {
        "request_type": state.request_type.value,
        "regulation": state.regulation.value,
        "total_records": state.total_records,
        "systems_processed": state.systems_processed,
        "fulfilled": state.request_fulfilled,
        "compliance_score": compliance,
    }

    # LLM enhancement for report
    try:
        ctx = _json.dumps(
            {
                "subject": state.subject_email,
                "request_type": state.request_type.value,
                "regulation": state.regulation.value,
                "locations_count": len(state.data_locations),
                "classifications": state.classifications[:5],
                "action_results": state.action_results[:5],
                "verification": state.verification,
                "fulfilled": state.request_fulfilled,
            },
            default=str,
        )
        llm_out = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate compliance report:\n{ctx}",
            schema=ComplianceReportOutput,
        )
        if isinstance(llm_out, ComplianceReportOutput):
            report.update(
                {
                    "executive_summary": (llm_out.executive_summary),
                    "recommendations": (llm_out.recommendations),
                    "compliance_gaps": (llm_out.compliance_gaps),
                    "compliance_rating": (llm_out.compliance_rating),
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

    # Track metrics
    await toolkit.record_metric(
        request_id=state.request_id,
        outcome={
            "fulfilled": state.request_fulfilled,
            "total_records": state.total_records,
            "systems_processed": state.systems_processed,
            "compliance_score": compliance,
            "duration_ms": state.session_duration_ms,
        },
    )

    duration_ms = 0
    if state.session_start:
        delta = datetime.now(UTC) - state.session_start
        duration_ms = int(delta.total_seconds() * 1000)

    step = _step(
        state.reasoning_chain,
        "generate_report",
        f"Reporting on {state.systems_processed} systems",
        f"Report generated, compliance={compliance:.2f}",
        start,
        "report_generator",
    )

    return {
        "report": report,
        "compliance_score": compliance,
        "session_duration_ms": duration_ms,
        "stage": PRAStage.REPORT,
        "reasoning_chain": [*state.reasoning_chain, step],
        "current_step": "complete",
    }
