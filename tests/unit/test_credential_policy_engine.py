"""Tests for CredentialPolicyEngine."""

import pytest

from shieldops.security.credential_policy_engine import (
    ComplianceStatus,
    CredentialPolicyEngine,
    CredentialPolicyReport,
    PolicyScope,
)


@pytest.fixture
def engine():
    return CredentialPolicyEngine(max_records=100)


def test_add_policy(engine):
    policy = engine.add_policy("global-default", scope=PolicyScope.GLOBAL, max_ttl_seconds=3600)
    assert policy.name == "global-default"
    assert policy.scope == PolicyScope.GLOBAL
    assert len(engine._policies) == 1


def test_evaluate_compliant(engine):
    engine.add_policy("default", max_ttl_seconds=7200, max_scope_level="read_write")
    result = engine.evaluate("agent-1", request_scope="read_only", request_ttl=3600)
    assert result.status == ComplianceStatus.COMPLIANT
    assert len(result.violations) == 0


def test_evaluate_violation(engine):
    engine.add_policy("strict", max_ttl_seconds=1800, max_scope_level="read_only")
    result = engine.evaluate("agent-1", request_scope="admin", request_ttl=7200)
    assert result.status == ComplianceStatus.VIOLATION
    assert len(result.violations) >= 1


def test_evaluate_ttl_violation(engine):
    engine.add_policy("short-lived", max_ttl_seconds=600)
    result = engine.evaluate("agent-1", request_scope="read_only", request_ttl=3600)
    assert result.status == ComplianceStatus.VIOLATION
    assert any("ttl" in v for v in result.violations)


def test_get_applicable_policies(engine):
    engine.add_policy("global", scope=PolicyScope.GLOBAL, target="*")
    engine.add_policy("agent-specific", scope=PolicyScope.AGENT_SPECIFIC, target="agent-1")
    engine.add_policy("other-agent", scope=PolicyScope.AGENT_SPECIFIC, target="agent-2")
    applicable = engine.get_applicable_policies(agent_id="agent-1")
    assert len(applicable) == 2  # global + agent-specific
    names = {p.name for p in applicable}
    assert "global" in names
    assert "agent-specific" in names


def test_detect_policy_conflicts(engine):
    engine.add_policy(
        "policy-a",
        scope=PolicyScope.GLOBAL,
        target="*",
        max_ttl_seconds=3600,
        max_scope_level="read_only",
    )
    engine.add_policy(
        "policy-b",
        scope=PolicyScope.GLOBAL,
        target="*",
        max_ttl_seconds=7200,
        max_scope_level="admin",
    )
    conflicts = engine.detect_policy_conflicts()
    assert len(conflicts) == 1
    assert "policy-a" in conflicts[0]["policies"]


def test_detect_no_conflicts(engine):
    engine.add_policy(
        "policy-a",
        scope=PolicyScope.GLOBAL,
        target="*",
        max_ttl_seconds=3600,
        max_scope_level="read_only",
    )
    engine.add_policy(
        "policy-b",
        scope=PolicyScope.AGENT_SPECIFIC,
        target="agent-1",
        max_ttl_seconds=3600,
        max_scope_level="read_only",
    )
    conflicts = engine.detect_policy_conflicts()
    assert len(conflicts) == 0


def test_generate_report(engine):
    engine.add_policy("default")
    engine.evaluate("agent-1", request_scope="read_only", request_ttl=3600)
    report = engine.generate_report()
    assert isinstance(report, CredentialPolicyReport)
    assert report.total_policies == 1
    assert report.total_evaluations == 1


def test_get_stats(engine):
    engine.add_policy("default")
    engine.evaluate("agent-1")
    stats = engine.get_stats()
    assert "total_policies" in stats
    assert "total_evaluations" in stats
    assert "compliant" in stats
    assert "violations" in stats


def test_clear_data(engine):
    engine.add_policy("default")
    engine.evaluate("agent-1")
    engine.clear_data()
    assert len(engine._policies) == 0
    assert len(engine._evaluations) == 0
