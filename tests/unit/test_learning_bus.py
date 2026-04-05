"""Behavioral TDD tests for the Learning Bus cross-agent pub/sub system.

Tests cover publish/subscribe delivery, scope-based filtering, priority and
confidence thresholds, event expiration, adoption tracking, buffer limits,
unsubscribe, query methods, shared patterns, and singleton behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from shieldops.utils.evolution_enums import LearningEventType, LearningPriority, PropagationScope
from shieldops.utils.learning_bus import (
    AGENT_TYPE_RELATIONSHIPS,
    MAX_EVENTS,
    LearningBus,
    get_learning_bus,
)


@pytest.fixture()  # type: ignore[misc]
def bus() -> LearningBus:
    """Fresh LearningBus instance for each test."""
    return LearningBus()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _publish_fleet_wide(bus: LearningBus, **overrides):  # type: ignore[no-untyped-def]
    """Publish a FLEET_WIDE event with sensible defaults."""
    defaults = dict(
        event_type=LearningEventType.PATTERN_DETECTED,
        source_agent_id="agent-src",
        source_agent_type="investigation",
        title="test event",
        scope=PropagationScope.FLEET_WIDE,
        confidence=0.8,
        priority=LearningPriority.MEDIUM,
    )
    defaults.update(overrides)
    return bus.publish(**defaults)  # type: ignore[arg-type]


# ===========================================================================
# Publish / Subscribe
# ===========================================================================


class TestPublishSubscribe:
    """Events published on the bus are delivered to subscribers via callback."""

    def test_publish_returns_learning_event(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus, title="sig learned")
        assert event.title == "sig learned"
        assert event.event_type == LearningEventType.PATTERN_DETECTED
        assert event.event_id  # non-empty

    def test_callback_invoked_on_matching_publish(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe("sub-1", subscriber_type="soc_analyst", callback=cb)
        event = _publish_fleet_wide(bus)

        cb.assert_called_once_with(event)

    def test_multiple_subscribers_each_receive_event(self, bus: LearningBus) -> None:
        cb1, cb2 = MagicMock(), MagicMock()
        bus.subscribe("sub-1", subscriber_type="soc_analyst", callback=cb1)
        bus.subscribe("sub-2", subscriber_type="threat_hunter", callback=cb2)
        _publish_fleet_wide(bus)

        assert cb1.call_count == 1
        assert cb2.call_count == 1

    def test_subscriber_without_callback_gets_pending_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        _publish_fleet_wide(bus)

        pending = bus.get_pending("sub-1")
        assert len(pending) == 1

    def test_callback_exception_does_not_prevent_other_deliveries(self, bus: LearningBus) -> None:
        bad_cb = MagicMock(side_effect=RuntimeError("boom"))
        good_cb = MagicMock()
        bus.subscribe("sub-bad", subscriber_type="soc_analyst", callback=bad_cb)
        bus.subscribe("sub-good", subscriber_type="threat_hunter", callback=good_cb)
        _publish_fleet_wide(bus)

        good_cb.assert_called_once()

    def test_event_stored_in_bus_after_publish(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, title="stored")
        events = bus.get_events()
        assert len(events) == 1
        assert events[0].title == "stored"

    def test_subscribe_with_specific_event_types_only(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe(
            "sub-1",
            subscriber_type="soc_analyst",
            event_types=[LearningEventType.ATTACK_SIGNATURE_LEARNED],
            callback=cb,
        )
        # Publish a non-matching type
        _publish_fleet_wide(bus, event_type=LearningEventType.PATTERN_DETECTED)
        cb.assert_not_called()

        # Publish matching type
        _publish_fleet_wide(bus, event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED)
        cb.assert_called_once()


# ===========================================================================
# Scope Filtering
# ===========================================================================


class TestScopeFiltering:
    """Events are delivered only to agents within the event's propagation scope."""

    def test_self_only_not_delivered_to_other_agents(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe("other-agent", subscriber_type="investigation", callback=cb)
        _publish_fleet_wide(
            bus,
            scope=PropagationScope.SELF_ONLY,
            source_agent_id="agent-src",
            source_agent_type="investigation",
        )
        cb.assert_not_called()

    def test_self_only_source_agent_skipped_by_self_delivery_prevention(
        self, bus: LearningBus
    ) -> None:
        """SELF_ONLY scope + self-delivery prevention = nobody receives the event."""
        cb = MagicMock()
        bus.subscribe("agent-src", subscriber_type="investigation", callback=cb)
        _publish_fleet_wide(
            bus,
            scope=PropagationScope.SELF_ONLY,
            source_agent_id="agent-src",
        )
        # Source agent is always excluded from propagation
        cb.assert_not_called()

    def test_same_type_delivered_to_same_type_only(self, bus: LearningBus) -> None:
        same_cb = MagicMock()
        diff_cb = MagicMock()
        bus.subscribe("sub-same", subscriber_type="investigation", callback=same_cb)
        bus.subscribe("sub-diff", subscriber_type="remediation", callback=diff_cb)

        _publish_fleet_wide(
            bus,
            scope=PropagationScope.SAME_TYPE,
            source_agent_type="investigation",
        )
        same_cb.assert_called_once()
        diff_cb.assert_not_called()

    def test_related_types_uses_relationship_graph(self, bus: LearningBus) -> None:
        # investigation relates to: soc_analyst, threat_hunter, forensics, incident_response
        related_cb = MagicMock()
        unrelated_cb = MagicMock()
        bus.subscribe("sub-related", subscriber_type="soc_analyst", callback=related_cb)
        bus.subscribe("sub-unrelated", subscriber_type="remediation", callback=unrelated_cb)

        _publish_fleet_wide(
            bus,
            scope=PropagationScope.RELATED_TYPES,
            source_agent_type="investigation",
        )
        related_cb.assert_called_once()
        unrelated_cb.assert_not_called()

    def test_related_types_includes_same_type(self, bus: LearningBus) -> None:
        """RELATED_TYPES should also match agents of the same type as source."""
        same_type_cb = MagicMock()
        bus.subscribe("sub-same", subscriber_type="investigation", callback=same_type_cb)

        _publish_fleet_wide(
            bus,
            scope=PropagationScope.RELATED_TYPES,
            source_agent_type="investigation",
        )
        same_type_cb.assert_called_once()

    def test_related_types_all_related_agents_receive(self, bus: LearningBus) -> None:
        """All entries in AGENT_TYPE_RELATIONSHIPS for the source type should receive."""
        callbacks = {}
        related = AGENT_TYPE_RELATIONSHIPS["investigation"]
        for agent_type in related:
            cb = MagicMock()
            callbacks[agent_type] = cb
            bus.subscribe(f"sub-{agent_type}", subscriber_type=agent_type, callback=cb)

        _publish_fleet_wide(
            bus,
            scope=PropagationScope.RELATED_TYPES,
            source_agent_type="investigation",
        )
        for agent_type, cb in callbacks.items():
            cb.assert_called_once(), f"{agent_type} should have been notified"  # type: ignore[func-returns-value]

    def test_related_types_no_relationships_defined(self, bus: LearningBus) -> None:
        """Source type not in AGENT_TYPE_RELATIONSHIPS delivers only to same type."""
        cb = MagicMock()
        bus.subscribe("sub-1", subscriber_type="some_other_type", callback=cb)

        _publish_fleet_wide(
            bus,
            scope=PropagationScope.RELATED_TYPES,
            source_agent_type="nonexistent_type",
        )
        cb.assert_not_called()

    def test_fleet_wide_delivered_to_all_subscribers(self, bus: LearningBus) -> None:
        cb1 = MagicMock()
        cb2 = MagicMock()
        bus.subscribe("sub-1", subscriber_type="investigation", callback=cb1)
        bus.subscribe("sub-2", subscriber_type="totally_different", callback=cb2)

        _publish_fleet_wide(bus)
        cb1.assert_called_once()
        cb2.assert_called_once()


# ===========================================================================
# Self-Delivery Prevention
# ===========================================================================


class TestSelfDeliveryPrevention:
    """Source agent never receives its own events, regardless of scope."""

    def test_source_agent_excluded_from_callback(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe("agent-src", subscriber_type="investigation", callback=cb)
        _publish_fleet_wide(bus, source_agent_id="agent-src")
        cb.assert_not_called()

    def test_source_agent_excluded_from_pending(self, bus: LearningBus) -> None:
        bus.subscribe("agent-src", subscriber_type="investigation")
        _publish_fleet_wide(bus, source_agent_id="agent-src")
        assert bus.get_pending("agent-src") == []

    def test_other_agents_still_receive_when_source_excluded(self, bus: LearningBus) -> None:
        src_cb = MagicMock()
        other_cb = MagicMock()
        bus.subscribe("agent-src", subscriber_type="investigation", callback=src_cb)
        bus.subscribe("agent-other", subscriber_type="investigation", callback=other_cb)

        _publish_fleet_wide(bus, source_agent_id="agent-src")
        src_cb.assert_not_called()
        other_cb.assert_called_once()


# ===========================================================================
# Priority & Confidence Filtering
# ===========================================================================


class TestPriorityConfidence:
    """Events are filtered by minimum priority level and confidence threshold."""

    @pytest.mark.parametrize(
        "event_priority,min_priority,should_deliver",
        [
            (LearningPriority.CRITICAL, LearningPriority.LOW, True),
            (LearningPriority.CRITICAL, LearningPriority.CRITICAL, True),
            (LearningPriority.HIGH, LearningPriority.HIGH, True),
            (LearningPriority.HIGH, LearningPriority.CRITICAL, False),
            (LearningPriority.MEDIUM, LearningPriority.HIGH, False),
            (LearningPriority.LOW, LearningPriority.MEDIUM, False),
            (LearningPriority.LOW, LearningPriority.LOW, True),
        ],
    )
    def test_priority_filtering(  # type: ignore[no-untyped-def]
        self, bus: LearningBus, event_priority, min_priority, should_deliver
    ) -> None:
        cb = MagicMock()
        bus.subscribe(
            "sub-1",
            subscriber_type="soc_analyst",
            min_priority=min_priority,
            callback=cb,
        )
        _publish_fleet_wide(bus, priority=event_priority)

        if should_deliver:
            cb.assert_called_once()
        else:
            cb.assert_not_called()

    @pytest.mark.parametrize(
        "event_confidence,min_confidence,should_deliver",
        [
            (0.9, 0.5, True),
            (0.5, 0.5, True),
            (0.49, 0.5, False),
            (0.0, 0.0, True),
            (1.0, 1.0, True),
            (0.99, 1.0, False),
        ],
    )
    def test_confidence_filtering(  # type: ignore[no-untyped-def]
        self, bus: LearningBus, event_confidence, min_confidence, should_deliver
    ) -> None:
        cb = MagicMock()
        bus.subscribe(
            "sub-1",
            subscriber_type="soc_analyst",
            min_confidence=min_confidence,
            callback=cb,
        )
        _publish_fleet_wide(bus, confidence=event_confidence)

        if should_deliver:
            cb.assert_called_once()
        else:
            cb.assert_not_called()

    def test_combined_priority_and_confidence_both_must_pass(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe(
            "sub-1",
            subscriber_type="soc_analyst",
            min_priority=LearningPriority.HIGH,
            min_confidence=0.7,
            callback=cb,
        )
        # High priority but low confidence -> rejected
        _publish_fleet_wide(bus, priority=LearningPriority.HIGH, confidence=0.3)
        cb.assert_not_called()

        # High confidence but low priority -> rejected
        _publish_fleet_wide(bus, priority=LearningPriority.LOW, confidence=0.9)
        cb.assert_not_called()

        # Both pass -> delivered
        _publish_fleet_wide(bus, priority=LearningPriority.HIGH, confidence=0.9)
        cb.assert_called_once()


# ===========================================================================
# Pending Events & Expiry
# ===========================================================================


class TestPendingAndExpiry:
    """Pending events exclude expired, applied, rejected, and self-sourced events."""

    def test_get_pending_returns_unconsumed_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        _publish_fleet_wide(bus, title="e1")
        _publish_fleet_wide(bus, title="e2")

        pending = bus.get_pending("sub-1")
        assert len(pending) == 2

    def test_get_pending_excludes_applied_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        event = _publish_fleet_wide(bus)
        bus.mark_applied(event.event_id, "sub-1")

        assert bus.get_pending("sub-1") == []

    def test_get_pending_excludes_rejected_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        event = _publish_fleet_wide(bus)
        bus.mark_rejected(event.event_id, "sub-1")

        assert bus.get_pending("sub-1") == []

    def test_get_pending_excludes_expired_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        with patch("shieldops.utils.learning_bus.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _publish_fleet_wide(bus, ttl_hours=1)  # expires at 4600

            # Now time is past expiry
            mock_time.time.return_value = 5000.0
            pending = bus.get_pending("sub-1")
            assert pending == []

    def test_get_pending_includes_non_expired_events(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        with patch("shieldops.utils.learning_bus.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _publish_fleet_wide(bus, ttl_hours=1)  # expires at 4600

            # Still within TTL
            mock_time.time.return_value = 2000.0
            pending = bus.get_pending("sub-1")
            assert len(pending) == 1

    def test_get_pending_respects_limit(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        for i in range(10):
            _publish_fleet_wide(bus, title=f"event-{i}")

        pending = bus.get_pending("sub-1", limit=3)
        assert len(pending) == 3

    def test_get_pending_respects_since_filter(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        old_event = _publish_fleet_wide(bus, title="old")
        old_event.published_at = 1000.0

        new_event = _publish_fleet_wide(bus, title="new")
        new_event.published_at = 2000.0

        pending = bus.get_pending("sub-1", since=1500.0)
        assert len(pending) == 1
        assert pending[0].title == "new"

    def test_get_pending_for_unsubscribed_agent_returns_empty(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus)
        assert bus.get_pending("no-such-subscriber") == []

    def test_get_pending_excludes_self_sourced_events(self, bus: LearningBus) -> None:
        bus.subscribe("agent-src", subscriber_type="soc_analyst")
        _publish_fleet_wide(bus, source_agent_id="agent-src")
        assert bus.get_pending("agent-src") == []


# ===========================================================================
# Adoption Tracking
# ===========================================================================


class TestAdoptionTracking:
    """mark_applied and mark_rejected track adoption; propagation report shows rates."""

    def test_mark_applied_returns_true_for_existing_event(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        assert bus.mark_applied(event.event_id, "agent-a") is True

    def test_mark_applied_returns_false_for_missing_event(self, bus: LearningBus) -> None:
        assert bus.mark_applied("nonexistent-id", "agent-a") is False

    def test_mark_applied_is_idempotent(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        bus.mark_applied(event.event_id, "agent-a")
        bus.mark_applied(event.event_id, "agent-a")
        assert event.applied_by.count("agent-a") == 1

    def test_mark_rejected_returns_true_for_existing_event(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        assert bus.mark_rejected(event.event_id, "agent-a") is True

    def test_mark_rejected_returns_false_for_missing_event(self, bus: LearningBus) -> None:
        assert bus.mark_rejected("nonexistent-id", "agent-a") is False

    def test_mark_rejected_is_idempotent(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        bus.mark_rejected(event.event_id, "agent-a")
        bus.mark_rejected(event.event_id, "agent-a")
        assert event.rejected_by.count("agent-a") == 1

    def test_propagation_report_shows_applied_and_rejected(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        bus.mark_applied(event.event_id, "agent-a")
        bus.mark_applied(event.event_id, "agent-b")
        bus.mark_rejected(event.event_id, "agent-c")

        report = bus.get_propagation_report(event.event_id)
        assert report is not None
        assert report.total_applied == 2
        assert report.total_rejected == 1
        assert report.total_subscribers_notified == 3
        assert report.application_rate == pytest.approx(2 / 3, abs=1e-4)

    def test_propagation_report_for_missing_event_returns_none(self, bus: LearningBus) -> None:
        assert bus.get_propagation_report("no-such-id") is None

    def test_propagation_report_zero_adopters(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        report = bus.get_propagation_report(event.event_id)
        assert report is not None
        assert report.total_applied == 0
        assert report.total_rejected == 0
        assert report.application_rate == pytest.approx(0.0)

    def test_propagation_report_preserves_event_metadata(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(
            bus,
            event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED,
            source_agent_id="agent-src",
        )
        report = bus.get_propagation_report(event.event_id)
        assert report.event_type == LearningEventType.ATTACK_SIGNATURE_LEARNED  # type: ignore[union-attr]
        assert report.source_agent == "agent-src"  # type: ignore[union-attr]


# ===========================================================================
# Buffer Limits
# ===========================================================================


class TestBufferLimits:
    """MAX_EVENTS is enforced, oldest events are evicted."""

    def test_events_beyond_max_evict_oldest(self, bus: LearningBus) -> None:
        for i in range(MAX_EVENTS + 50):
            _publish_fleet_wide(bus, title=f"event-{i}")

        assert len(bus._events) == MAX_EVENTS
        # Oldest events should have been evicted; newest remain
        assert bus._events[-1].title == f"event-{MAX_EVENTS + 49}"

    def test_events_at_max_are_not_evicted(self, bus: LearningBus) -> None:
        for i in range(MAX_EVENTS):
            _publish_fleet_wide(bus, title=f"event-{i}")

        assert len(bus._events) == MAX_EVENTS
        assert bus._events[0].title == "event-0"


# ===========================================================================
# Unsubscribe
# ===========================================================================


class TestUnsubscribe:
    """Unsubscribe removes the subscription and callback."""

    def test_unsubscribe_returns_true_for_existing(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        assert bus.unsubscribe("sub-1") is True

    def test_unsubscribe_returns_false_for_missing(self, bus: LearningBus) -> None:
        assert bus.unsubscribe("no-such-sub") is False

    def test_unsubscribed_agent_receives_no_further_events(self, bus: LearningBus) -> None:
        cb = MagicMock()
        bus.subscribe("sub-1", subscriber_type="soc_analyst", callback=cb)
        bus.unsubscribe("sub-1")

        _publish_fleet_wide(bus)
        cb.assert_not_called()

    def test_unsubscribed_agent_gets_empty_pending(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        _publish_fleet_wide(bus)
        bus.unsubscribe("sub-1")

        assert bus.get_pending("sub-1") == []


# ===========================================================================
# get_events Query
# ===========================================================================


class TestGetEvents:
    """get_events returns events matching optional filters."""

    def test_get_events_no_filters_returns_all(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, title="a")
        _publish_fleet_wide(bus, title="b")
        events = bus.get_events()
        assert len(events) == 2

    def test_get_events_filter_by_event_type(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, event_type=LearningEventType.PATTERN_DETECTED)
        _publish_fleet_wide(bus, event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED)

        events = bus.get_events(event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED)
        assert len(events) == 1
        assert events[0].event_type == LearningEventType.ATTACK_SIGNATURE_LEARNED

    def test_get_events_filter_by_source_agent_type(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, source_agent_type="investigation")
        _publish_fleet_wide(bus, source_agent_type="remediation")

        events = bus.get_events(source_agent_type="remediation")
        assert len(events) == 1
        assert events[0].source_agent_type == "remediation"

    def test_get_events_filter_by_min_confidence(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, confidence=0.3)
        _publish_fleet_wide(bus, confidence=0.9)

        events = bus.get_events(min_confidence=0.5)
        assert len(events) == 1
        assert events[0].confidence == pytest.approx(0.9)

    def test_get_events_respects_limit(self, bus: LearningBus) -> None:
        for _ in range(10):
            _publish_fleet_wide(bus)
        events = bus.get_events(limit=3)
        assert len(events) == 3

    def test_get_events_excludes_expired_by_default(self, bus: LearningBus) -> None:
        with patch("shieldops.utils.learning_bus.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _publish_fleet_wide(bus, ttl_hours=1)  # expires at 4600

            mock_time.time.return_value = 5000.0
            assert bus.get_events() == []

    def test_get_events_include_expired_flag(self, bus: LearningBus) -> None:
        with patch("shieldops.utils.learning_bus.time") as mock_time:
            mock_time.time.return_value = 1000.0
            _publish_fleet_wide(bus, ttl_hours=1)

            mock_time.time.return_value = 5000.0
            events = bus.get_events(include_expired=True)
            assert len(events) == 1


# ===========================================================================
# get_shared_patterns
# ===========================================================================


class TestGetSharedPatterns:
    """get_shared_patterns returns events with >= min_applications."""

    def test_returns_events_with_enough_applications(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus, event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED)
        bus.mark_applied(event.event_id, "a1")
        bus.mark_applied(event.event_id, "a2")
        bus.mark_applied(event.event_id, "a3")

        patterns = bus.get_shared_patterns(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            min_applications=3,
        )
        assert len(patterns) == 1
        assert patterns[0].event_id == event.event_id

    def test_excludes_events_below_threshold(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus, event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED)
        bus.mark_applied(event.event_id, "a1")
        bus.mark_applied(event.event_id, "a2")

        patterns = bus.get_shared_patterns(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            min_applications=3,
        )
        assert patterns == []

    def test_filters_by_event_type(self, bus: LearningBus) -> None:
        fp = _publish_fleet_wide(bus, event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED)
        sig = _publish_fleet_wide(bus, event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED)
        for eid in [fp.event_id, sig.event_id]:
            for agent in ["a1", "a2", "a3"]:
                bus.mark_applied(eid, agent)

        patterns = bus.get_shared_patterns(
            event_type=LearningEventType.FALSE_POSITIVE_DISCOVERED,
            min_applications=3,
        )
        assert len(patterns) == 1
        assert patterns[0].event_type == LearningEventType.FALSE_POSITIVE_DISCOVERED


# ===========================================================================
# get_stats
# ===========================================================================


class TestGetStats:
    """get_stats returns bus statistics."""

    def test_empty_bus_stats(self, bus: LearningBus) -> None:
        stats = bus.get_stats()
        assert stats["total_events"] == 0
        assert stats["active_events"] == 0
        assert stats["total_subscribers"] == 0

    def test_stats_reflect_events_and_subscribers(self, bus: LearningBus) -> None:
        bus.subscribe("sub-1", subscriber_type="soc_analyst")
        _publish_fleet_wide(bus)
        _publish_fleet_wide(bus)

        stats = bus.get_stats()
        assert stats["total_events"] == 2
        assert stats["total_subscribers"] == 1

    def test_stats_events_by_type(self, bus: LearningBus) -> None:
        _publish_fleet_wide(bus, event_type=LearningEventType.PATTERN_DETECTED)
        _publish_fleet_wide(bus, event_type=LearningEventType.PATTERN_DETECTED)
        _publish_fleet_wide(bus, event_type=LearningEventType.ATTACK_SIGNATURE_LEARNED)

        stats = bus.get_stats()
        assert stats["events_by_type"][LearningEventType.PATTERN_DETECTED] == 2
        assert stats["events_by_type"][LearningEventType.ATTACK_SIGNATURE_LEARNED] == 1

    def test_stats_application_rate(self, bus: LearningBus) -> None:
        event = _publish_fleet_wide(bus)
        bus.mark_applied(event.event_id, "a1")
        bus.mark_rejected(event.event_id, "a2")

        stats = bus.get_stats()
        # 1 applied / (1 applied + 1 rejected) = 0.5, averaged over 1 event = 0.5
        assert stats["avg_application_rate"] == pytest.approx(0.5, abs=1e-4)


# ===========================================================================
# Singleton
# ===========================================================================


class TestSingleton:
    """get_learning_bus() returns the same instance."""

    def test_singleton_returns_same_instance(self) -> None:
        with patch("shieldops.utils.learning_bus._bus", None):
            bus1 = get_learning_bus()
            bus2 = get_learning_bus()
            assert bus1 is bus2

    def test_singleton_returns_learning_bus_type(self) -> None:
        with patch("shieldops.utils.learning_bus._bus", None):
            bus = get_learning_bus()
            assert isinstance(bus, LearningBus)
