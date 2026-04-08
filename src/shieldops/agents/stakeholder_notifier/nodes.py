"""Node implementations for the Stakeholder Notifier."""

from __future__ import annotations

import json as _json
import time
from typing import Any

import structlog

from shieldops.utils.llm import llm_structured

from .models import SNStage
from .prompts import (
    SYSTEM_ANALYZE,
    SYSTEM_REPORT,
    AnalyzeOutput,
    ReportOutput,
)
from .tools import StakeholderNotifierToolkit

logger = structlog.get_logger()

_toolkit: StakeholderNotifierToolkit | None = None


def _get_toolkit() -> StakeholderNotifierToolkit:
    if _toolkit is None:
        return StakeholderNotifierToolkit()
    return _toolkit


async def identify_stakeholders(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Identify stakeholders to notify."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.identify_stakeholders(
        incident_severity=state.get(
            "incident_severity",
            "",
        ),
        affected_services=state.get(
            "affected_services",
            [],
        ),
        incident_description=state.get(
            "incident_description",
            "",
        ),
    )

    try:
        ctx = _json.dumps(
            {
                "title": state.get("incident_title", ""),
                "severity": state.get(
                    "incident_severity",
                    "",
                ),
                "description": state.get(
                    "incident_description",
                    "",
                ),
                "services": state.get(
                    "affected_services",
                    [],
                ),
            },
            default=str,
        )
        llm = await llm_structured(
            system_prompt=SYSTEM_ANALYZE,
            user_prompt=f"Analyze stakeholders:\n{ctx}",
            schema=AnalyzeOutput,
        )
        if hasattr(llm, "affected_groups"):
            for stk in result:
                stk["llm_validated"] = stk.get("group") in llm.affected_groups
    except Exception:
        logger.debug("sn.llm_skipped", node="identify")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "identify_stakeholders",
        "stage": SNStage.ASSESS_IMPACT.value,
        "stakeholders": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "identify_stakeholders",
                "detail": f"Groups={len(result)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "identify_ms": elapsed,
        },
    }


async def assess_impact(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Assess communication impact."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.assess_impact(
        stakeholders=state.get("stakeholders", []),
        affected_services=state.get(
            "affected_services",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "assess_impact",
        "stage": SNStage.COMPOSE_MESSAGE.value,
        "impact_assessment": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "assess_impact",
                "detail": (f"Contacts={result.get('total_contacts')}"),
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "impact_ms": elapsed,
        },
    }


async def compose_message(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Compose targeted messages."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.compose_message(
        stakeholders=state.get("stakeholders", []),
        incident_title=state.get("incident_title", ""),
        incident_description=state.get(
            "incident_description",
            "",
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "compose_message",
        "stage": SNStage.SELECT_CHANNELS.value,
        "composed_messages": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "compose_message",
                "detail": f"Messages={len(result)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "compose_ms": elapsed,
        },
    }


async def select_channels(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Select delivery channels."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.select_channels(
        stakeholders=state.get("stakeholders", []),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "select_channels",
        "stage": SNStage.DELIVER_NOTIFICATION.value,
        "selected_channels": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "select_channels",
                "detail": f"Channel sets={len(result)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "channels_ms": elapsed,
        },
    }


async def deliver_notification(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Deliver notifications."""
    start = time.time()
    tk = _get_toolkit()

    result = await tk.deliver_notification(
        composed_messages=state.get(
            "composed_messages",
            [],
        ),
        selected_channels=state.get(
            "selected_channels",
            [],
        ),
    )

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "deliver_notification",
        "stage": SNStage.REPORT.value,
        "delivery_results": result,
        "reasoning_chain": [
            *chain,
            {
                "step": "deliver_notification",
                "detail": f"Delivered={len(result)}",
                "elapsed_ms": elapsed,
            },
        ],
        "stats": {
            **state.get("stats", {}),
            "deliver_ms": elapsed,
        },
    }


async def report(
    state: dict[str, Any],
) -> dict[str, Any]:
    """Generate notification summary report."""
    start = time.time()
    deliveries = state.get("delivery_results", [])
    report_data: dict[str, Any] = {
        "total_stakeholders": len(
            state.get("stakeholders", []),
        ),
        "messages_composed": len(
            state.get("composed_messages", []),
        ),
        "total_deliveries": len(deliveries),
        "delivered": sum(1 for d in deliveries if d.get("status") == "delivered"),
    }

    try:
        ctx = _json.dumps(report_data, default=str)
        llm = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate report:\n{ctx}",
            schema=ReportOutput,
        )
        if hasattr(llm, "executive_summary"):
            report_data["executive_summary"] = llm.executive_summary
            report_data["recommended_followups"] = llm.recommended_followups
    except Exception:
        logger.debug("sn.llm_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    chain = state.get("reasoning_chain", [])
    return {
        "current_step": "report",
        "stage": SNStage.REPORT.value,
        "stats": {
            **state.get("stats", {}),
            **report_data,
            "report_ms": elapsed,
        },
        "reasoning_chain": [
            *chain,
            {
                "step": "report",
                "detail": "Notification report generated",
                "elapsed_ms": elapsed,
            },
        ],
    }
