"""Node implementations for the Incident Communicator Agent LangGraph workflow."""

from __future__ import annotations

import json as _json
import time
from typing import Any
from uuid import uuid4

import structlog

from shieldops.agents.incident_communicator.models import (
    ChannelType,
    CommStage,
    IncidentCommunicatorState,
    MessagePriority,
    Notification,
)
from shieldops.agents.incident_communicator.prompts import (
    SYSTEM_COMPOSE_MESSAGE,
    SYSTEM_IDENTIFY_STAKEHOLDERS,
    SYSTEM_REPORT,
    MessageOutput,
    ReportOutput,
    StakeholderOutput,
)
from shieldops.agents.incident_communicator.tools import (
    PRIORITY_CHANNELS,
    IncidentCommunicatorToolkit,
)
from shieldops.utils.llm import llm_structured

logger = structlog.get_logger()

_toolkit: IncidentCommunicatorToolkit | None = None


def set_toolkit(toolkit: IncidentCommunicatorToolkit) -> None:
    """Set the shared toolkit instance for all nodes."""
    global _toolkit  # noqa: PLW0603
    _toolkit = toolkit


def _get_toolkit() -> IncidentCommunicatorToolkit:
    if _toolkit is None:
        return IncidentCommunicatorToolkit()
    return _toolkit


def _severity_from_incident(incident_id: str) -> str:
    """Derive a default severity hint from the incident_id convention."""
    return "medium"


# ------------------------------------------------------------------
# Node: identify_stakeholders
# ------------------------------------------------------------------


async def identify_stakeholders(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Identify who needs to be notified about this incident."""
    start = time.time()
    toolkit = _get_toolkit()
    severity = "medium"

    # Toolkit-based identification
    stakeholders = await toolkit.identify_stakeholders(
        incident_id=state.incident_id,
        severity=severity,
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "severity": severity,
                "heuristic_stakeholders": stakeholders,
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_IDENTIFY_STAKEHOLDERS,
            user_prompt=f"Identify stakeholders for:\n{context}",
            schema=StakeholderOutput,
        )
        if hasattr(llm_result, "stakeholders") and llm_result.stakeholders:
            stakeholders = llm_result.stakeholders
        reasoning = getattr(llm_result, "reasoning", "")
        logger.info("llm_enhanced", node="identify_stakeholders")
    except Exception:
        reasoning = f"Identified {len(stakeholders)} stakeholder(s) via heuristic"
        logger.debug("llm_enhancement_skipped", node="identify_stakeholders")

    # Build initial Notification objects (without messages yet)
    notifications: list[Notification] = []
    for sh in stakeholders:
        priority_str = sh.get("priority", "medium")
        try:
            priority = MessagePriority(priority_str)
        except ValueError:
            priority = MessagePriority.MEDIUM

        notifications.append(
            Notification(
                id=f"ntf-{uuid4().hex[:12]}",
                recipient=sh.get("name", "Unknown"),
                priority=priority,
            )
        )

    elapsed = int((time.time() - start) * 1000)
    return {
        "notifications": notifications,
        "stage": CommStage.DRAFT_MESSAGES,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"identify_stakeholders: {reasoning} ({elapsed}ms)",
        ],
        "session_start": (start if state.session_start == 0.0 else state.session_start),
    }


# ------------------------------------------------------------------
# Node: draft_messages
# ------------------------------------------------------------------


async def draft_messages(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Draft notification messages for each stakeholder."""
    start = time.time()
    toolkit = _get_toolkit()
    updated: list[Notification] = []

    for notif in state.notifications:
        severity = notif.priority.value
        message = await toolkit.draft_message(
            incident_id=state.incident_id,
            severity=severity,
            recipient=notif.recipient,
        )

        # LLM enhancement
        try:
            context = _json.dumps(
                {
                    "incident_id": state.incident_id,
                    "severity": severity,
                    "recipient": notif.recipient,
                    "heuristic_message": message,
                },
                default=str,
            )
            llm_result = await llm_structured(
                system_prompt=SYSTEM_COMPOSE_MESSAGE,
                user_prompt=f"Draft message:\n{context}",
                schema=MessageOutput,
            )
            llm_body = getattr(llm_result, "body", "")
            if llm_body:
                subject = getattr(llm_result, "subject", "")
                message = f"{subject}\n\n{llm_body}" if subject else llm_body
            logger.info(
                "llm_enhanced",
                node="draft_messages",
                recipient=notif.recipient,
            )
        except Exception:
            logger.debug(
                "llm_enhancement_skipped",
                node="draft_messages",
                recipient=notif.recipient,
            )

        updated.append(notif.model_copy(update={"message": message}))

    elapsed = int((time.time() - start) * 1000)
    return {
        "notifications": updated,
        "stage": CommStage.SELECT_CHANNELS,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"draft_messages: drafted {len(updated)} message(s) ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: select_channels
# ------------------------------------------------------------------


async def select_channels(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Select the best channel for each notification based on priority."""
    start = time.time()
    updated: list[Notification] = []
    channels_used: set[str] = set()

    for notif in state.notifications:
        priority_key = notif.priority.value
        preferred = PRIORITY_CHANNELS.get(priority_key, ["slack"])
        channel_value = preferred[0] if preferred else "slack"
        try:
            channel = ChannelType(channel_value)
        except ValueError:
            channel = ChannelType.SLACK

        channels_used.add(channel.value)
        updated.append(notif.model_copy(update={"channel": channel}))

    elapsed = int((time.time() - start) * 1000)
    return {
        "notifications": updated,
        "channels_used": sorted(channels_used),
        "stage": CommStage.SEND_NOTIFICATIONS,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"select_channels: assigned channels {sorted(channels_used)} ({elapsed}ms)"),
        ],
    }


# ------------------------------------------------------------------
# Node: send_notifications
# ------------------------------------------------------------------


async def send_notifications(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Send all notifications via their assigned channels."""
    start = time.time()
    toolkit = _get_toolkit()
    updated: list[Notification] = []
    sent_count = 0

    for notif in state.notifications:
        success = await toolkit.send_notification(notif)
        updated.append(notif.model_copy(update={"sent": success}))
        if success:
            sent_count += 1

    elapsed = int((time.time() - start) * 1000)
    return {
        "notifications": updated,
        "stage": CommStage.TRACK_ACKS,
        "reasoning_chain": [
            *state.reasoning_chain,
            (f"send_notifications: {sent_count}/{len(updated)} delivered ({elapsed}ms)"),
        ],
    }


# ------------------------------------------------------------------
# Node: track_acks
# ------------------------------------------------------------------


async def track_acks(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Check acknowledgment status for sent notifications."""
    start = time.time()
    toolkit = _get_toolkit()
    updated: list[Notification] = []
    ack_count = 0

    for notif in state.notifications:
        if not notif.sent:
            updated.append(notif)
            continue
        acked = await toolkit.check_acknowledgment(notif.id)
        updated.append(notif.model_copy(update={"acknowledged": acked}))
        if acked:
            ack_count += 1

    elapsed = int((time.time() - start) * 1000)
    return {
        "notifications": updated,
        "ack_count": ack_count,
        "stage": CommStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"track_acks: {ack_count}/{len(updated)} acknowledged ({elapsed}ms)",
        ],
    }


# ------------------------------------------------------------------
# Node: report
# ------------------------------------------------------------------


async def report(
    state: IncidentCommunicatorState,
) -> dict[str, Any]:
    """Generate a communication summary report."""
    start = time.time()
    total_elapsed = int((time.time() - state.session_start) * 1000)

    total = len(state.notifications)
    sent = sum(1 for n in state.notifications if n.sent)
    acked = sum(1 for n in state.notifications if n.acknowledged)
    delivery_rate = (sent / total * 100) if total else 0.0
    ack_rate = (acked / total * 100) if total else 0.0

    summary = (
        f"Incident {state.incident_id}: {total} notification(s), "
        f"{sent} delivered ({delivery_rate:.0f}%), "
        f"{acked} acknowledged ({ack_rate:.0f}%)"
    )

    # LLM enhancement
    try:
        context = _json.dumps(
            {
                "incident_id": state.incident_id,
                "total_notifications": total,
                "delivered": sent,
                "acknowledged": acked,
                "delivery_rate": delivery_rate,
                "ack_rate": ack_rate,
                "channels_used": state.channels_used,
                "notifications": [n.model_dump() for n in state.notifications],
            },
            default=str,
        )
        llm_result = await llm_structured(
            system_prompt=SYSTEM_REPORT,
            user_prompt=f"Generate communication report:\n{context}",
            schema=ReportOutput,
        )
        llm_summary = getattr(llm_result, "executive_summary", "")
        if llm_summary:
            summary = llm_summary
        logger.info("llm_enhanced", node="report")
    except Exception:
        logger.debug("llm_enhancement_skipped", node="report")

    elapsed = int((time.time() - start) * 1000)
    return {
        "stage": CommStage.REPORT,
        "reasoning_chain": [
            *state.reasoning_chain,
            f"report: {summary} ({elapsed}ms, total {total_elapsed}ms)",
        ],
    }
