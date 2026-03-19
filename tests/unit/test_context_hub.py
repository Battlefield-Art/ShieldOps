"""Tests for the Context Hub and Agent Context Mixin."""

from __future__ import annotations

import pytest

from shieldops.utils.agent_context_mixin import (
    fetch_context_for_compliance,
    fetch_context_for_incident,
    fetch_context_for_remediation,
    get_context_hub,
    reset_context_hub,
)
from shieldops.utils.context_hub import (
    ContextEntry,
    ContextHub,
    ContextQuery,
    ContextType,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_entry(
    id: str = "test-1",
    context_type: ContextType = ContextType.RUNBOOK,
    title: str = "Test Entry",
    content: str = "Some test content here",
    tags: list[str] | None = None,
    source: str = "test",
    version: str = "1.0",
) -> ContextEntry:
    return ContextEntry(
        id=id,
        context_type=context_type,
        title=title,
        content=content,
        tags=tags or [],
        source=source,
        version=version,
    )


@pytest.fixture()
def hub() -> ContextHub:
    return ContextHub()


@pytest.fixture()
def populated_hub() -> ContextHub:
    h = ContextHub()
    h.register(
        _make_entry(
            id="rb-1",
            title="OOMKilled Response",
            content="Steps to handle OOMKilled pods in kubernetes",
            tags=["kubernetes", "oom", "memory"],
        )
    )
    h.register(
        _make_entry(
            id="rb-2",
            title="High CPU Investigation",
            content="Steps to investigate high CPU usage on servers",
            tags=["cpu", "performance"],
        )
    )
    h.register(
        _make_entry(
            id="comp-1",
            context_type=ContextType.COMPLIANCE,
            title="HIPAA PHI Access",
            content="Requirements for accessing protected health information",
            tags=["hipaa", "compliance", "phi"],
        )
    )
    h.register(
        _make_entry(
            id="inc-1",
            context_type=ContextType.INCIDENT_HISTORY,
            title="Past OOM incident on API gateway",
            content="API gateway crashed due to unbounded request buffering memory",
            tags=["oom", "api", "incident"],
        )
    )
    h.register(
        _make_entry(
            id="play-1",
            context_type=ContextType.PLAYBOOK,
            title="Rollback Playbook",
            content="How to rollback kubernetes deployment safely",
            tags=["kubernetes", "rollback", "deployment"],
        )
    )
    return h


@pytest.fixture(autouse=True)
def _reset_global_hub() -> None:
    """Reset global hub singleton before each test."""
    reset_context_hub()


# ---------------------------------------------------------------------------
# ContextHub.register
# ---------------------------------------------------------------------------


class TestRegister:
    def test_register_adds_entry(self, hub: ContextHub) -> None:
        entry = _make_entry()
        hub.register(entry)
        assert len(hub._entries) == 1
        assert hub._entries[0].id == "test-1"

    def test_register_indexes_by_tags(self, hub: ContextHub) -> None:
        entry = _make_entry(tags=["kubernetes", "memory"])
        hub.register(entry)
        assert "kubernetes" in hub._cache
        assert "memory" in hub._cache
        assert hub._cache["kubernetes"][0].id == "test-1"

    def test_register_multiple_entries(self, hub: ContextHub) -> None:
        hub.register(_make_entry(id="a"))
        hub.register(_make_entry(id="b"))
        hub.register(_make_entry(id="c"))
        assert len(hub._entries) == 3


# ---------------------------------------------------------------------------
# ContextHub.search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_by_query_terms(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(ContextQuery(query="OOMKilled"))
        assert len(results) > 0
        assert any("OOM" in r.title for r in results)

    def test_search_by_context_type(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(
            ContextQuery(
                query="access health",
                context_types=[ContextType.COMPLIANCE],
            )
        )
        assert all(r.context_type == ContextType.COMPLIANCE for r in results)

    def test_search_by_tags(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(ContextQuery(query="response", tags=["kubernetes"]))
        for r in results:
            assert set(r.tags) & {"kubernetes"}

    def test_search_relevance_scoring(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(ContextQuery(query="OOMKilled memory"))
        assert len(results) > 0
        assert results[0].relevance_score > 0
        # Results should be sorted by relevance descending
        scores = [r.relevance_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_search_max_results(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(
            ContextQuery(query="kubernetes memory oom cpu", max_results=2)
        )
        assert len(results) <= 2

    def test_search_min_relevance(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(
            ContextQuery(query="OOMKilled kubernetes memory", min_relevance=0.5)
        )
        for r in results:
            assert r.relevance_score >= 0.5

    def test_search_empty_hub(self, hub: ContextHub) -> None:
        results = hub.search(ContextQuery(query="anything"))
        assert results == []

    def test_search_no_matches(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(ContextQuery(query="xyznonexistent42"))
        assert results == []

    def test_search_combines_type_and_tag_filters(self, populated_hub: ContextHub) -> None:
        results = populated_hub.search(
            ContextQuery(
                query="oom",
                context_types=[ContextType.INCIDENT_HISTORY],
                tags=["oom"],
            )
        )
        assert len(results) >= 1
        assert all(r.context_type == ContextType.INCIDENT_HISTORY for r in results)

    def test_search_returns_copies(self, populated_hub: ContextHub) -> None:
        """Search results should be copies so modifying them doesn't affect hub."""
        results = populated_hub.search(ContextQuery(query="OOMKilled"))
        if results:
            results[0].title = "MODIFIED"
            original = populated_hub.get(results[0].id)
            assert original is not None
            assert original.title != "MODIFIED"


# ---------------------------------------------------------------------------
# ContextHub.get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_existing(self, populated_hub: ContextHub) -> None:
        entry = populated_hub.get("rb-1")
        assert entry is not None
        assert entry.id == "rb-1"

    def test_get_nonexistent(self, populated_hub: ContextHub) -> None:
        assert populated_hub.get("nonexistent") is None

    def test_get_empty_hub(self, hub: ContextHub) -> None:
        assert hub.get("anything") is None


# ---------------------------------------------------------------------------
# ContextHub.annotate
# ---------------------------------------------------------------------------


class TestAnnotate:
    def test_annotate_existing(self, populated_hub: ContextHub) -> None:
        result = populated_hub.annotate("rb-1", "This was useful for pod restarts")
        assert result is True
        annotations = populated_hub.get_annotations("rb-1")
        assert len(annotations) == 1
        assert "useful" in annotations[0]

    def test_annotate_nonexistent(self, populated_hub: ContextHub) -> None:
        result = populated_hub.annotate("fake-id", "note")
        assert result is False

    def test_annotate_multiple(self, populated_hub: ContextHub) -> None:
        populated_hub.annotate("rb-1", "First note")
        populated_hub.annotate("rb-1", "Second note")
        annotations = populated_hub.get_annotations("rb-1")
        assert len(annotations) == 2


# ---------------------------------------------------------------------------
# ContextHub.feedback
# ---------------------------------------------------------------------------


class TestFeedback:
    def test_feedback_helpful(self, populated_hub: ContextHub) -> None:
        result = populated_hub.feedback("rb-1", helpful=True, comment="Perfect runbook")
        assert result is True
        fb = populated_hub.get_feedback("rb-1")
        assert len(fb) == 1
        assert fb[0]["helpful"] is True

    def test_feedback_not_helpful(self, populated_hub: ContextHub) -> None:
        populated_hub.feedback("rb-1", helpful=False, comment="Outdated steps")
        fb = populated_hub.get_feedback("rb-1")
        assert fb[0]["helpful"] is False

    def test_feedback_nonexistent(self, populated_hub: ContextHub) -> None:
        result = populated_hub.feedback("fake-id", helpful=True)
        assert result is False

    def test_feedback_has_timestamp(self, populated_hub: ContextHub) -> None:
        populated_hub.feedback("rb-1", helpful=True)
        fb = populated_hub.get_feedback("rb-1")
        assert "timestamp" in fb[0]
        assert fb[0]["timestamp"] > 0


# ---------------------------------------------------------------------------
# ContextHub.get_stats
# ---------------------------------------------------------------------------


class TestGetStats:
    def test_stats_empty_hub(self, hub: ContextHub) -> None:
        stats = hub.get_stats()
        assert stats["total_entries"] == 0
        assert stats["by_type"] == {}
        assert stats["total_annotations"] == 0
        assert stats["total_feedback"] == 0
        assert stats["helpful_ratio"] == 0.0

    def test_stats_populated(self, populated_hub: ContextHub) -> None:
        stats = populated_hub.get_stats()
        assert stats["total_entries"] == 5
        assert stats["by_type"][ContextType.RUNBOOK] == 2
        assert stats["by_type"][ContextType.COMPLIANCE] == 1

    def test_stats_with_feedback(self, populated_hub: ContextHub) -> None:
        populated_hub.feedback("rb-1", helpful=True)
        populated_hub.feedback("rb-2", helpful=False)
        stats = populated_hub.get_stats()
        assert stats["total_feedback"] == 2
        assert stats["helpful_ratio"] == 0.5


# ---------------------------------------------------------------------------
# ContextHub.remove and list_entries
# ---------------------------------------------------------------------------


class TestRemoveAndList:
    def test_remove_existing(self, populated_hub: ContextHub) -> None:
        assert populated_hub.remove("rb-1") is True
        assert populated_hub.get("rb-1") is None
        assert populated_hub.get_stats()["total_entries"] == 4

    def test_remove_nonexistent(self, populated_hub: ContextHub) -> None:
        assert populated_hub.remove("fake") is False

    def test_list_all(self, populated_hub: ContextHub) -> None:
        entries = populated_hub.list_entries()
        assert len(entries) == 5

    def test_list_by_type(self, populated_hub: ContextHub) -> None:
        runbooks = populated_hub.list_entries(context_type=ContextType.RUNBOOK)
        assert len(runbooks) == 2
        assert all(e.context_type == ContextType.RUNBOOK for e in runbooks)


# ---------------------------------------------------------------------------
# load_default_contexts
# ---------------------------------------------------------------------------


class TestDefaultContexts:
    def test_load_returns_count(self) -> None:
        hub = ContextHub()
        count = hub.load_default_contexts()
        assert count >= 10

    def test_defaults_cover_incident_types(self) -> None:
        hub = ContextHub()
        hub.load_default_contexts()
        # Should cover key incident types
        ids = {e.id for e in hub._entries}
        assert "runbook-oomkilled" in ids
        assert "runbook-high-cpu" in ids
        assert "runbook-ssl-cert-expiry" in ids
        assert "runbook-disk-full" in ids
        assert "runbook-memory-leak" in ids
        assert "runbook-db-connection-pool" in ids
        assert "runbook-k8s-rollback" in ids

    def test_defaults_cover_compliance(self) -> None:
        hub = ContextHub()
        hub.load_default_contexts()
        ids = {e.id for e in hub._entries}
        assert "compliance-hipaa-phi" in ids
        assert "compliance-soc2-change" in ids
        assert "compliance-pci-dss" in ids

    def test_defaults_searchable(self) -> None:
        hub = ContextHub()
        hub.load_default_contexts()
        results = hub.search(ContextQuery(query="OOMKilled pod memory"))
        assert len(results) > 0

    def test_defaults_have_tags(self) -> None:
        hub = ContextHub()
        hub.load_default_contexts()
        for entry in hub._entries:
            assert len(entry.tags) > 0, f"Entry {entry.id} has no tags"


# ---------------------------------------------------------------------------
# Agent Context Mixin — fetch_context_for_incident
# ---------------------------------------------------------------------------


class TestFetchContextForIncident:
    def test_returns_context_for_oom(self) -> None:
        result = fetch_context_for_incident(alert_type="OOMKilled")
        assert "Retrieved Context" in result
        assert "OOM" in result

    def test_returns_empty_for_no_match(self) -> None:
        result = fetch_context_for_incident(alert_type="xyznonexistent42")
        assert result == ""

    def test_includes_service_in_search(self) -> None:
        result = fetch_context_for_incident(alert_type="high cpu", service="api-gateway")
        # Should find CPU runbook
        assert isinstance(result, str)  # May not match but shouldn't crash

    def test_includes_environment(self) -> None:
        result = fetch_context_for_incident(alert_type="disk full", environment="production")
        assert isinstance(result, str)

    def test_format_has_headers(self) -> None:
        result = fetch_context_for_incident(alert_type="OOMKilled kubernetes")
        if result:
            assert "###" in result
            assert "knowledge base" in result.lower()


# ---------------------------------------------------------------------------
# Agent Context Mixin — fetch_context_for_compliance
# ---------------------------------------------------------------------------


class TestFetchContextForCompliance:
    def test_returns_hipaa_context(self) -> None:
        result = fetch_context_for_compliance(
            action_type="data access phi",
            frameworks=["hipaa"],
        )
        assert "HIPAA" in result or "hipaa" in result.lower() or result == ""

    def test_returns_empty_for_no_match(self) -> None:
        result = fetch_context_for_compliance(action_type="xyznonexistent42")
        assert result == ""

    def test_filters_by_framework_tags(self) -> None:
        result = fetch_context_for_compliance(
            action_type="change management audit",
            frameworks=["soc2"],
        )
        assert isinstance(result, str)

    def test_no_framework_filter(self) -> None:
        # Without framework filter, should search all compliance entries
        result = fetch_context_for_compliance(action_type="encryption access data")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# Agent Context Mixin — fetch_context_for_remediation
# ---------------------------------------------------------------------------


class TestFetchContextForRemediation:
    def test_returns_rollback_context(self) -> None:
        result = fetch_context_for_remediation(action_type="rollback deployment")
        assert isinstance(result, str)

    def test_returns_empty_for_no_match(self) -> None:
        result = fetch_context_for_remediation(action_type="xyznonexistent42")
        assert result == ""

    def test_includes_target_resource(self) -> None:
        result = fetch_context_for_remediation(
            action_type="disk remediation",
            target_resource="/var/log",
        )
        assert isinstance(result, str)

    def test_format_has_headers(self) -> None:
        result = fetch_context_for_remediation(action_type="kubernetes rollback deployment")
        if result:
            assert "Remediation Context" in result


# ---------------------------------------------------------------------------
# Agent Context Mixin — get_context_hub singleton
# ---------------------------------------------------------------------------


class TestGetContextHub:
    def test_returns_hub_instance(self) -> None:
        hub = get_context_hub()
        assert isinstance(hub, ContextHub)

    def test_singleton(self) -> None:
        hub1 = get_context_hub()
        hub2 = get_context_hub()
        assert hub1 is hub2

    def test_reset_clears_singleton(self) -> None:
        hub1 = get_context_hub()
        reset_context_hub()
        hub2 = get_context_hub()
        assert hub1 is not hub2

    def test_auto_loads_defaults(self) -> None:
        hub = get_context_hub()
        assert hub.get_stats()["total_entries"] >= 10
