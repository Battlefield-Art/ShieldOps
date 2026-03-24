"""Tests for MCPPermissionAnalyzer engine."""

import pytest

from shieldops.security.mcp_permission_analyzer import (
    AnalysisOutcome,
    MCPPermissionAnalyzer,
    PermissionAnalyzerReport,
    PermissionLevel,
)


@pytest.fixture
def engine():
    return MCPPermissionAnalyzer(max_records=100)


def test_record_permission(engine):
    rec = engine.record_permission("mcp-1", "read_tool", level=PermissionLevel.READ, used=True)
    assert rec.server_id == "mcp-1"
    assert rec.tool_name == "read_tool"
    assert rec.level == PermissionLevel.READ
    assert rec.used is True
    assert len(engine._permissions) == 1


def test_analyze_server_optimal(engine):
    engine.record_permission(
        "mcp-1", "read_tool", level=PermissionLevel.READ, used=True, usage_count=10
    )
    engine.record_permission(
        "mcp-1", "write_tool", level=PermissionLevel.WRITE, used=True, usage_count=5
    )
    analysis = engine.analyze_server("mcp-1")
    assert analysis.outcome == AnalysisOutcome.OPTIMAL
    assert analysis.over_privileged == 0


def test_analyze_server_over_privileged(engine):
    engine.record_permission(
        "mcp-1", "admin_tool", level=PermissionLevel.ADMIN, used=False, usage_count=0
    )
    analysis = engine.analyze_server("mcp-1")
    assert analysis.outcome == AnalysisOutcome.OVER_PRIVILEGED
    assert analysis.over_privileged == 1


def test_detect_excessive_permissions(engine):
    engine.record_permission("mcp-1", "admin_tool", level=PermissionLevel.ADMIN, usage_count=0)
    engine.record_permission("mcp-1", "read_tool", level=PermissionLevel.READ, usage_count=10)
    excessive = engine.detect_excessive_permissions()
    assert len(excessive) == 1
    assert excessive[0].tool_name == "admin_tool"


def test_detect_unused_permissions(engine):
    rec = engine.record_permission("mcp-1", "unused_tool", level=PermissionLevel.WRITE, used=False)
    # Make it appear old
    rec.created_at = rec.created_at - 40 * 86400
    unused = engine.detect_unused_permissions(stale_days=30)
    assert len(unused) == 1
    assert unused[0].tool_name == "unused_tool"


def test_detect_unused_permissions_recent(engine):
    engine.record_permission("mcp-1", "new_tool", level=PermissionLevel.WRITE, used=False)
    # Created just now, so not stale
    unused = engine.detect_unused_permissions(stale_days=30)
    assert len(unused) == 0


def test_generate_report(engine):
    engine.record_permission("mcp-1", "tool_a", level=PermissionLevel.ADMIN, usage_count=0)
    engine.analyze_server("mcp-1")
    report = engine.generate_report()
    assert isinstance(report, PermissionAnalyzerReport)
    assert report.total_permissions == 1
    assert report.total_analyses == 1
    assert report.over_privileged_count == 1


def test_generate_report_empty(engine):
    report = engine.generate_report()
    assert report.total_permissions == 0
    assert "Permission scoping is optimal" in report.recommendations


def test_get_stats(engine):
    engine.record_permission("mcp-1", "tool_a")
    stats = engine.get_stats()
    assert "total_permissions" in stats
    assert "total_analyses" in stats
    assert "unique_servers" in stats
    assert "unique_tools" in stats
    assert stats["total_permissions"] == 1


def test_clear_data(engine):
    engine.record_permission("mcp-1", "tool_a")
    engine.analyze_server("mcp-1")
    engine.clear_data()
    assert len(engine._permissions) == 0
    assert len(engine._analyses) == 0
