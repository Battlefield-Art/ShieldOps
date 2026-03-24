"""Tests for MCPConfigAuditor engine."""

import pytest

from shieldops.security.mcp_config_auditor import (
    FindingCategory,
    FindingSeverity,
    MCPConfigAuditor,
    MCPConfigAuditReport,
)


@pytest.fixture
def engine():
    return MCPConfigAuditor(max_records=100)


def test_audit_config_secure(engine):
    config = {
        "auth": "oauth2",
        "transport": "https",
        "logging": "enabled",
        "allowed_tools": "read_logs",
    }
    findings = engine.audit_config(config)
    assert len(findings) == 0


def test_audit_config_insecure(engine):
    config = {
        "auth": "none",
        "transport": "http",
        "logging": "disabled",
        "allowed_tools": "*",
    }
    findings = engine.audit_config(config)
    assert len(findings) >= 3  # auth, transport, logging, wildcard tools
    severities = {f.severity for f in findings}
    assert FindingSeverity.CRITICAL in severities
    assert FindingSeverity.HIGH in severities


def test_add_rule(engine):
    initial_count = len(engine._rules)
    rule = engine.add_rule(
        name="custom_check",
        category=FindingCategory.DATA_EXPOSURE,
        severity=FindingSeverity.HIGH,
        check_field="encryption",
        expected_values=["aes256", "aes128"],
        description="Encryption must be configured",
    )
    assert len(engine._rules) == initial_count + 1
    assert rule.name == "custom_check"


def test_custom_rule_triggers(engine):
    engine.add_rule(
        name="require_encryption",
        check_field="encryption",
        expected_values=["aes256"],
        severity=FindingSeverity.HIGH,
    )
    findings = engine.audit_config(
        {"auth": "oauth2", "transport": "https", "logging": "enabled", "encryption": "none"}
    )
    assert any(f.config_path == "encryption" for f in findings)


def test_detect_insecure_defaults(engine):
    issues = engine.detect_insecure_defaults({"auth": "none", "transport": "http"})
    assert len(issues) == 2
    fields = {i["field"] for i in issues}
    assert "auth" in fields
    assert "transport" in fields


def test_detect_insecure_defaults_secure(engine):
    issues = engine.detect_insecure_defaults({"auth": "oauth2", "transport": "https"})
    assert len(issues) == 0


def test_detect_excessive_tool_permissions(engine):
    issues = engine.detect_excessive_tool_permissions({"allowed_tools": ["*"]})
    assert len(issues) == 1
    assert issues[0]["issue"] == "wildcard_tools"


def test_detect_excessive_tool_permissions_clean(engine):
    issues = engine.detect_excessive_tool_permissions({"allowed_tools": ["read", "write"]})
    assert len(issues) == 0


def test_generate_report(engine):
    engine.audit_config({"auth": "none", "transport": "http", "logging": "no"})
    report = engine.generate_report()
    assert isinstance(report, MCPConfigAuditReport)
    assert report.total_findings > 0
    assert report.total_audits == 1


def test_generate_report_empty(engine):
    report = engine.generate_report()
    assert report.total_findings == 0
    assert "MCP configurations pass all audit rules" in report.recommendations


def test_get_stats(engine):
    engine.audit_config({"auth": "none"})
    stats = engine.get_stats()
    assert "total_audits" in stats
    assert "total_findings" in stats
    assert "total_rules" in stats
    assert "custom_rules" in stats
    assert stats["total_audits"] == 1


def test_clear_data(engine):
    engine.audit_config({"auth": "none"})
    engine.add_rule(name="extra")
    engine.clear_data()
    assert len(engine._findings) == 0
    assert engine._audit_count == 0
    # custom rules cleared, defaults restored
    assert len(engine._rules) == 4
