"""Tests for MCPSecurityGateway engine."""

import pytest

from shieldops.security.mcp_security_gateway import (
    AuthRequirement,
    GatewayAction,
    GatewayReport,
    MCPSecurityGateway,
)


@pytest.fixture
def engine():
    return MCPSecurityGateway(max_records=200)


def test_evaluate_request_allow(engine):
    engine.add_policy(
        server_pattern="mcp-prod.*",
        allowed_agents=["agent-1"],
        auth_requirement=AuthRequirement.API_KEY,
        allowed_tools=["read", "write"],
    )
    result = engine.evaluate_request(
        server_endpoint="mcp-prod-01",
        agent_id="agent-1",
        tool_name="read",
        auth_token="valid-token",
    )
    assert result["action"] == GatewayAction.ALLOW


def test_evaluate_request_block_agent(engine):
    engine.add_policy(
        server_pattern="mcp-prod.*",
        allowed_agents=["agent-1"],
        auth_requirement=AuthRequirement.API_KEY,
    )
    result = engine.evaluate_request(
        server_endpoint="mcp-prod-01",
        agent_id="agent-rogue",
        tool_name="read",
        auth_token="valid-token",
    )
    assert result["action"] == GatewayAction.BLOCK
    assert any("not_in_allowlist" in r for r in result["reasons"])


def test_evaluate_request_no_policy(engine):
    result = engine.evaluate_request(
        server_endpoint="unknown-server",
        agent_id="agent-1",
        tool_name="read",
    )
    assert result["action"] == GatewayAction.AUDIT_ONLY


def test_evaluate_request_require_auth(engine):
    engine.add_policy(
        server_pattern="mcp-secure.*",
        auth_requirement=AuthRequirement.OAUTH2,
    )
    result = engine.evaluate_request(
        server_endpoint="mcp-secure-01",
        agent_id="agent-1",
        tool_name="read",
        auth_token=None,
    )
    assert result["action"] == GatewayAction.REQUIRE_AUTH


def test_evaluate_request_blocked_tool(engine):
    engine.add_policy(
        server_pattern="mcp-prod.*",
        auth_requirement=AuthRequirement.NONE,
        blocked_tools=["delete_all"],
    )
    result = engine.evaluate_request(
        server_endpoint="mcp-prod-01",
        agent_id="agent-1",
        tool_name="delete_all",
    )
    assert result["action"] == GatewayAction.BLOCK


def test_record_event(engine):
    rec = engine.record_event(
        server_endpoint="mcp-prod-01",
        agent_id="agent-1",
        tool_name="read",
        action=GatewayAction.ALLOW,
    )
    assert rec.server_endpoint == "mcp-prod-01"
    assert rec.agent_id == "agent-1"
    assert len(engine._events) == 1


def test_add_policy(engine):
    policy = engine.add_policy(
        server_pattern="mcp-dev.*",
        auth_requirement=AuthRequirement.NONE,
        rate_limit_per_minute=100,
    )
    assert policy.server_pattern == "mcp-dev.*"
    assert len(engine._policies) == 1


def test_check_rate_limit(engine):
    engine.add_policy(
        server_pattern="mcp-prod.*", rate_limit_per_minute=5, auth_requirement=AuthRequirement.NONE
    )
    for _ in range(4):
        engine.record_event("mcp-prod-01", "agent-1", "read")
    assert engine.check_rate_limit("mcp-prod-01", "agent-1") is True
    engine.record_event("mcp-prod-01", "agent-1", "read")
    assert engine.check_rate_limit("mcp-prod-01", "agent-1") is False


def test_detect_anomalous_access(engine):
    # Record 101 events to trigger burst detection
    for i in range(101):
        engine.record_event("mcp-prod-01", f"agent-{i % 20}", "read")
    anomalies = engine.detect_anomalous_access("mcp-prod-01", window_minutes=15)
    assert len(anomalies) >= 1
    assert any(a["type"] == "burst_access" for a in anomalies)


def test_detect_anomalous_access_clean(engine):
    for _i in range(5):
        engine.record_event("mcp-prod-01", "agent-1", "read")
    anomalies = engine.detect_anomalous_access("mcp-prod-01", window_minutes=15)
    assert len(anomalies) == 0


def test_generate_report(engine):
    engine.record_event("mcp-prod-01", "agent-1", "read", action=GatewayAction.ALLOW)
    engine.record_event("mcp-prod-01", "agent-2", "write", action=GatewayAction.BLOCK)
    report = engine.generate_gateway_report()
    assert isinstance(report, GatewayReport)
    assert report.total_events == 2
    assert report.blocked_count == 1
    assert report.allowed_count == 1


def test_get_stats(engine):
    engine.record_event("mcp-prod-01", "agent-1", "read")
    stats = engine.get_stats()
    assert "total_events" in stats
    assert "policy_count" in stats
    assert "action_distribution" in stats
    assert "unique_servers" in stats
    assert "unique_agents" in stats


def test_clear_data(engine):
    engine.record_event("mcp-prod-01", "agent-1", "read")
    engine.add_policy(server_pattern="mcp-.*")
    engine.clear_data()
    assert len(engine._events) == 0
    assert len(engine._policies) == 0
