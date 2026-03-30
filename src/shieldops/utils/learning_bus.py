"""Learning Bus — cross-agent pub/sub for learning event propagation.

Enables agents to publish learnings (false positive patterns, attack signatures,
threshold adjustments, playbook improvements) that other agents can subscribe to
and incorporate into their own behavior.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from enum import StrEnum
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class LearningEventType(StrEnum):
    """Categories of cross-agent learning events."""

    FALSE_POSITIVE_DISCOVERED = "false_positive_discovered"
    ATTACK_SIGNATURE_LEARNED = "attack_signature_learned"
    THRESHOLD_OPTIMIZED = "threshold_optimized"
    PLAYBOOK_IMPROVED = "playbook_improved"
    PATTERN_DETECTED = "pattern_detected"
    PROMPT_EVOLVED = "prompt_evolved"
    REMEDIATION_VALIDATED = "remediation_validated"
    ESCALATION_REFINED = "escalation_refined"
    DETECTION_RULE_TUNED = "detection_rule_tuned"
    CONTEXT_ENRICHED = "context_enriched"


class PropagationScope(StrEnum):
    """How widely a learning event should propagate."""

    SELF_ONLY = "self_only"
    SAME_TYPE = "same_type"
    RELATED_TYPES = "related_types"
    FLEET_WIDE = "fleet_wide"


class LearningPriority(StrEnum):
    """Priority of learning propagation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class LearningEvent(BaseModel):
    """A learning event published by an agent for cross-agent propagation."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    event_type: LearningEventType = LearningEventType.PATTERN_DETECTED
    source_agent_id: str = ""
    source_agent_type: str = ""
    priority: LearningPriority = LearningPriority.MEDIUM
    scope: PropagationScope = PropagationScope.SAME_TYPE
    title: str = ""
    description: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    published_at: float = Field(default_factory=time.time)
    expires_at: float = 0.0
    applied_by: list[str] = Field(default_factory=list)
    rejected_by: list[str] = Field(default_factory=list)


class Subscription(BaseModel):
    """An agent's subscription to specific learning event types."""

    subscriber_id: str = ""
    subscriber_type: str = ""
    event_types: list[LearningEventType] = Field(default_factory=list)
    min_priority: LearningPriority = LearningPriority.LOW
    min_confidence: float = 0.0
    created_at: float = Field(default_factory=time.time)


class PropagationReport(BaseModel):
    """Report of how a learning event propagated across the fleet."""

    event_id: str = ""
    event_type: LearningEventType = LearningEventType.PATTERN_DETECTED
    source_agent: str = ""
    total_subscribers_notified: int = 0
    total_applied: int = 0
    total_rejected: int = 0
    application_rate: float = 0.0


# ---------------------------------------------------------------------------
# Relationship mapping for RELATED_TYPES propagation
# ---------------------------------------------------------------------------

AGENT_TYPE_RELATIONSHIPS: dict[str, list[str]] = {
    "investigation": ["soc_analyst", "threat_hunter", "forensics", "incident_response"],
    "remediation": ["auto_remediation", "runbook_automation", "incident_response"],
    "soc_analyst": ["investigation", "threat_hunter", "soc_brain", "ai_soc_assistant"],
    "threat_hunter": ["investigation", "soc_analyst", "threat_intel", "forensics"],
    "detection_engineering": ["threat_hunter", "soc_analyst", "alert_correlation"],
    "security_testing": ["ai_red_team", "adversarial_validation", "vulnerability_manager"],
    "incident_response": ["investigation", "remediation", "incident_triage", "incident_commander"],
    "compliance_auditor": ["compliance_scanner", "compliance_reporter", "audit_compliance"],
    "autonomous_xdr": ["autonomous_soc", "alert_correlation", "xdr"],
    "identity_graph": ["identity_protection", "access_review", "oauth_analyzer"],
    "cloud_posture": ["container_security", "cloud_risk_ranker", "cnapp_analyzer"],
    "supply_chain_scanner": ["code_security_scanner", "supply_chain_security"],
    "prompt_shield": ["agent_firewall", "ai_runtime_defense", "model_security"],
}

# ---------------------------------------------------------------------------
# Learning Bus
# ---------------------------------------------------------------------------

MAX_EVENTS = 10_000
MAX_EVENTS_PER_TYPE = 1_000


class LearningBus:
    """Cross-agent learning event bus with pub/sub, propagation, and tracking.

    Agents publish learnings (false positives, new attack signatures, optimized
    thresholds). Subscribed agents receive relevant events and can apply or
    reject them. The bus tracks propagation success across the fleet.
    """

    def __init__(self) -> None:
        # All events, newest first
        self._events: list[LearningEvent] = []
        # subscriber_id → Subscription
        self._subscriptions: dict[str, Subscription] = {}
        # Callback registry: subscriber_id → callback
        self._callbacks: dict[str, Callable[[LearningEvent], None]] = {}
        # Per-type event count for limits
        self._type_counts: dict[LearningEventType, int] = defaultdict(int)

    # ----- Publishing -----

    def publish(
        self,
        event_type: LearningEventType,
        source_agent_id: str,
        source_agent_type: str,
        title: str,
        description: str = "",
        payload: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        confidence: float = 0.5,
        priority: LearningPriority = LearningPriority.MEDIUM,
        scope: PropagationScope = PropagationScope.SAME_TYPE,
        ttl_hours: float = 168,  # 7 days default
    ) -> LearningEvent:
        """Publish a learning event to the bus.

        Notifies all matching subscribers synchronously via callbacks.
        """
        event = LearningEvent(
            event_type=event_type,
            source_agent_id=source_agent_id,
            source_agent_type=source_agent_type,
            priority=priority,
            scope=scope,
            title=title,
            description=description,
            payload=payload or {},
            tags=tags or [],
            confidence=confidence,
            expires_at=time.time() + ttl_hours * 3600,
        )

        self._events.append(event)
        self._type_counts[event_type] += 1

        # Enforce limits
        if len(self._events) > MAX_EVENTS:
            self._events = self._events[-MAX_EVENTS:]

        # Notify matching subscribers
        notified = self._propagate(event)

        logger.info(
            "learning_bus.published",
            event_type=event_type,
            source=source_agent_id,
            title=title,
            confidence=round(confidence, 3),
            scope=scope,
            subscribers_notified=notified,
        )
        return event

    # ----- Subscribing -----

    def subscribe(
        self,
        subscriber_id: str,
        subscriber_type: str = "",
        event_types: list[LearningEventType] | None = None,
        min_priority: LearningPriority = LearningPriority.LOW,
        min_confidence: float = 0.0,
        callback: Callable[[LearningEvent], None] | None = None,
    ) -> Subscription:
        """Subscribe an agent to receive learning events.

        If callback is provided, it will be called synchronously for each
        matching event. Otherwise events accumulate for polling via get_pending().
        """
        sub = Subscription(
            subscriber_id=subscriber_id,
            subscriber_type=subscriber_type,
            event_types=event_types or list(LearningEventType),
            min_priority=min_priority,
            min_confidence=min_confidence,
        )
        self._subscriptions[subscriber_id] = sub
        if callback:
            self._callbacks[subscriber_id] = callback

        logger.debug(
            "learning_bus.subscribed",
            subscriber=subscriber_id,
            event_types=len(sub.event_types),
        )
        return sub

    def unsubscribe(self, subscriber_id: str) -> bool:
        """Remove a subscription."""
        removed = self._subscriptions.pop(subscriber_id, None) is not None
        self._callbacks.pop(subscriber_id, None)
        return removed

    # ----- Consuming -----

    def get_pending(
        self,
        subscriber_id: str,
        limit: int = 50,
        since: float = 0.0,
    ) -> list[LearningEvent]:
        """Get pending learning events for a subscriber (poll-based).

        Returns events that match the subscriber's filters and haven't been
        applied or rejected by this subscriber yet.
        """
        sub = self._subscriptions.get(subscriber_id)
        if not sub:
            return []

        now = time.time()
        results: list[LearningEvent] = []

        for event in reversed(self._events):
            if len(results) >= limit:
                break
            if event.published_at < since:
                break
            if event.expires_at and event.expires_at < now:
                continue
            if not self._matches(event, sub):
                continue
            if subscriber_id in event.applied_by or subscriber_id in event.rejected_by:
                continue
            # Don't send agent its own events
            if event.source_agent_id == subscriber_id:
                continue
            results.append(event)

        return results

    def mark_applied(self, event_id: str, agent_id: str) -> bool:
        """Mark a learning event as applied by an agent."""
        for event in self._events:
            if event.event_id == event_id:
                if agent_id not in event.applied_by:
                    event.applied_by.append(agent_id)
                return True
        return False

    def mark_rejected(self, event_id: str, agent_id: str) -> bool:
        """Mark a learning event as rejected by an agent."""
        for event in self._events:
            if event.event_id == event_id:
                if agent_id not in event.rejected_by:
                    event.rejected_by.append(agent_id)
                return True
        return False

    # ----- Querying -----

    def get_events(
        self,
        event_type: LearningEventType | None = None,
        source_agent_type: str | None = None,
        min_confidence: float = 0.0,
        limit: int = 50,
        include_expired: bool = False,
    ) -> list[LearningEvent]:
        """Query learning events with filters."""
        now = time.time()
        results: list[LearningEvent] = []

        for event in reversed(self._events):
            if len(results) >= limit:
                break
            if not include_expired and event.expires_at and event.expires_at < now:
                continue
            if event_type and event.event_type != event_type:
                continue
            if source_agent_type and event.source_agent_type != source_agent_type:
                continue
            if event.confidence < min_confidence:
                continue
            results.append(event)

        return results

    def get_propagation_report(self, event_id: str) -> PropagationReport | None:
        """Get propagation stats for a specific event."""
        for event in self._events:
            if event.event_id == event_id:
                total = len(event.applied_by) + len(event.rejected_by)
                return PropagationReport(
                    event_id=event_id,
                    event_type=event.event_type,
                    source_agent=event.source_agent_id,
                    total_subscribers_notified=total,
                    total_applied=len(event.applied_by),
                    total_rejected=len(event.rejected_by),
                    application_rate=round(len(event.applied_by) / max(total, 1), 4),
                )
        return None

    def get_shared_patterns(
        self,
        event_type: LearningEventType = LearningEventType.FALSE_POSITIVE_DISCOVERED,
        min_applications: int = 3,
    ) -> list[LearningEvent]:
        """Get learning events that have been widely applied across agents.

        These represent validated cross-agent patterns.
        """
        return [
            event
            for event in self._events
            if event.event_type == event_type and len(event.applied_by) >= min_applications
        ]

    # ----- Stats -----

    def get_stats(self) -> dict[str, Any]:
        """Learning bus statistics."""
        now = time.time()
        active_events = [e for e in self._events if not e.expires_at or e.expires_at > now]
        return {
            "total_events": len(self._events),
            "active_events": len(active_events),
            "total_subscribers": len(self._subscriptions),
            "events_by_type": {
                et: sum(1 for e in active_events if e.event_type == et)
                for et in LearningEventType
                if sum(1 for e in active_events if e.event_type == et) > 0
            },
            "events_by_scope": {
                scope: sum(1 for e in active_events if e.scope == scope)
                for scope in PropagationScope
                if sum(1 for e in active_events if e.scope == scope) > 0
            },
            "avg_application_rate": round(
                sum(
                    len(e.applied_by) / max(len(e.applied_by) + len(e.rejected_by), 1)
                    for e in active_events
                )
                / max(len(active_events), 1),
                4,
            ),
            "most_applied_events": [
                {"event_id": e.event_id, "title": e.title, "applied_by": len(e.applied_by)}
                for e in sorted(active_events, key=lambda x: len(x.applied_by), reverse=True)[:5]
            ],
        }

    # ----- Internal -----

    def _propagate(self, event: LearningEvent) -> int:
        """Propagate an event to matching subscribers. Returns count notified."""
        notified = 0
        for sub_id, sub in self._subscriptions.items():
            if sub_id == event.source_agent_id:
                continue
            if not self._matches(event, sub):
                continue
            if not self._scope_matches(event, sub):
                continue

            # Invoke callback if registered
            cb = self._callbacks.get(sub_id)
            if cb:
                try:
                    cb(event)
                except Exception:
                    logger.warning(
                        "learning_bus.callback_error",
                        subscriber=sub_id,
                        event_id=event.event_id,
                    )
            notified += 1

        return notified

    def _matches(self, event: LearningEvent, sub: Subscription) -> bool:
        """Check if an event matches a subscription's type/priority/confidence filters."""
        if event.event_type not in sub.event_types:
            return False
        if event.confidence < sub.min_confidence:
            return False

        # Priority ordering: CRITICAL > HIGH > MEDIUM > LOW
        priority_order = {
            LearningPriority.LOW: 0,
            LearningPriority.MEDIUM: 1,
            LearningPriority.HIGH: 2,
            LearningPriority.CRITICAL: 3,
        }
        return priority_order.get(event.priority, 0) >= priority_order.get(sub.min_priority, 0)

    def _scope_matches(self, event: LearningEvent, sub: Subscription) -> bool:
        """Check if subscriber is within the event's propagation scope."""
        if event.scope == PropagationScope.FLEET_WIDE:
            return True
        if event.scope == PropagationScope.SELF_ONLY:
            return sub.subscriber_id == event.source_agent_id
        if event.scope == PropagationScope.SAME_TYPE:
            return sub.subscriber_type == event.source_agent_type
        if event.scope == PropagationScope.RELATED_TYPES:
            related = AGENT_TYPE_RELATIONSHIPS.get(event.source_agent_type, [])
            return sub.subscriber_type in related or sub.subscriber_type == event.source_agent_type
        return False


# Module-level singleton
_bus: LearningBus | None = None


def get_learning_bus() -> LearningBus:
    """Get or create the global learning bus."""
    global _bus
    if _bus is None:
        _bus = LearningBus()
    return _bus
