"""Resilience tests for firewall graceful degradation when dependencies are unavailable."""

from __future__ import annotations

import asyncio

from shieldops.cache.firewall_cache import FirewallDecisionCache
from shieldops.security.agent_behavioral_firewall import (
    AgentBehavioralFirewall,
    FirewallAction,
)
from shieldops.security.agent_tool_call_interceptor import (
    AgentToolCallInterceptor,
    CallDecision,
)


def _run(coro):  # type: ignore[no-untyped-call]
    """Helper to run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# FirewallDecisionCache — local fallback when Redis is None
# ---------------------------------------------------------------------------


class TestCacheDegradation:
    """Verify FirewallDecisionCache works without Redis via local fallback."""

    def test_cache_works_without_redis(self) -> None:
        cache = FirewallDecisionCache(redis_client=None)
        decision = {"action": "allow", "risk": 0.1}
        _run(cache.set_decision("agent-1", "tool-a", "abc123", decision))  # type: ignore[no-untyped-call]
        result = _run(cache.get_decision("agent-1", "tool-a", "abc123"))  # type: ignore[no-untyped-call]
        assert result == decision

    def test_cache_stats_track_correctly(self) -> None:
        cache = FirewallDecisionCache(redis_client=None)
        decision = {"action": "block", "risk": 0.9}
        _run(cache.set_decision("agent-2", "tool-b", "xyz", decision))  # type: ignore[no-untyped-call]

        # Hit
        _run(cache.get_decision("agent-2", "tool-b", "xyz"))  # type: ignore[no-untyped-call]
        # Miss
        _run(cache.get_decision("agent-2", "tool-b", "missing"))  # type: ignore[no-untyped-call]

        stats = cache.get_stats()
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1

    def test_cache_invalidate_agent(self) -> None:
        cache = FirewallDecisionCache(redis_client=None)
        decision = {"action": "allow"}
        _run(cache.set_decision("agent-3", "tool-c", "h1", decision))  # type: ignore[no-untyped-call]

        # Confirm it is cached
        assert _run(cache.get_decision("agent-3", "tool-c", "h1")) is not None  # type: ignore[no-untyped-call]

        # Invalidate
        deleted = _run(cache.invalidate_agent("agent-3"))  # type: ignore[no-untyped-call]
        assert deleted >= 1

        # After invalidation, should be a miss
        result = _run(cache.get_decision("agent-3", "tool-c", "h1"))  # type: ignore[no-untyped-call]
        assert result is None


# ---------------------------------------------------------------------------
# AgentToolCallInterceptor — policy enforcement
# ---------------------------------------------------------------------------


class TestInterceptorDegradation:
    """Verify interceptor behavior with and without policies."""

    def test_interceptor_no_policies_allows(self) -> None:
        interceptor = AgentToolCallInterceptor()
        result = interceptor.intercept("agent-x", "any_tool")
        assert result["decision"] == CallDecision.PROCEED.value

    def test_interceptor_with_blocking_policy(self) -> None:
        interceptor = AgentToolCallInterceptor()
        # Add a policy that matches "delete_*" with very low rate limit
        interceptor.add_policy(tool_pattern="delete_*", max_rate=0)
        # Pre-populate a record so rate check can fail
        interceptor.record_call("agent-y", "delete_db", decision=CallDecision.PROCEED)
        result = interceptor.intercept("agent-y", "delete_db", context={"data_bytes": 0})
        assert result["decision"] == CallDecision.BLOCK.value


# ---------------------------------------------------------------------------
# AgentBehavioralFirewall — graceful handling with no data
# ---------------------------------------------------------------------------


class TestFirewallDegradation:
    """Verify firewall handles missing baselines and empty state gracefully."""

    def test_firewall_no_baseline_handles_gracefully(self) -> None:
        fw = AgentBehavioralFirewall()
        result = fw.evaluate_call("unknown-agent", "some_tool")
        assert "action" in result
        assert result["action"] == "allow"
        assert "no_baseline" in result["reasons"]

    def test_firewall_empty_report(self) -> None:
        fw = AgentBehavioralFirewall()
        report = fw.generate_report()
        assert report.total_events == 0
        assert report.blocked_count == 0
        assert len(report.recommendations) > 0  # always has at least one recommendation

    def test_firewall_ring_buffer(self) -> None:
        max_records = 100
        fw = AgentBehavioralFirewall(max_records=max_records)
        for i in range(max_records + 100):
            fw.record_event(f"agent-{i % 5}", f"tool-{i}")
        # Internal buffer should be capped at max_records
        assert len(fw._records) == max_records

    def test_firewall_clear_data(self) -> None:
        fw = AgentBehavioralFirewall()
        fw.record_event("agent-z", "tool-z", action=FirewallAction.BLOCK, risk_score=0.8)
        fw.build_baseline("agent-z")
        result = fw.clear_data()
        assert result == {"status": "cleared"}
        stats = fw.get_stats()
        assert stats["total_events"] == 0
        assert stats["total_profiles"] == 0
