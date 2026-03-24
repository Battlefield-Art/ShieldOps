"""Tests for MCPDependencyScanner engine."""

import time

import pytest

from shieldops.security.mcp_dependency_scanner import (
    DependencyScanReport,
    DependencyStatus,
    MCPDependencyScanner,
    ScanResult,
)


@pytest.fixture
def engine():
    return MCPDependencyScanner(max_records=100)


def test_register_dependency(engine):
    rec = engine.register_dependency("requests", version="2.31.0", server_id="mcp-1")
    assert rec.package_name == "requests"
    assert rec.version == "2.31.0"
    assert rec.server_id == "mcp-1"
    assert len(engine._dependencies) == 1


def test_scan_dependencies_clean(engine):
    engine.register_dependency("requests", version="2.31.0", server_id="mcp-1")
    scan = engine.scan_dependencies(server_id="mcp-1")
    assert scan.result == ScanResult.CLEAN
    assert scan.vulnerable_count == 0


def test_scan_dependencies_vulnerable(engine):
    engine.register_dependency("old-lib", version="1.0.0", server_id="mcp-1")
    vuln_db = {"old-lib": ["CVE-2024-0001", "CVE-2024-0002"]}
    scan = engine.scan_dependencies(server_id="mcp-1", vuln_db=vuln_db)
    assert scan.result == ScanResult.VULNERABLE
    assert scan.vulnerable_count == 1


def test_detect_abandoned(engine):
    rec = engine.register_dependency("ancient-lib", version="0.1.0", server_id="mcp-1")
    rec.last_updated = time.time() - 400 * 86400  # 400 days old
    abandoned = engine.detect_abandoned(stale_days=365)
    assert len(abandoned) == 1
    assert abandoned[0].status == DependencyStatus.ABANDONED


def test_detect_version_conflicts(engine):
    engine.register_dependency("requests", version="2.28.0", server_id="mcp-1")
    engine.register_dependency("requests", version="2.31.0", server_id="mcp-2")
    conflicts = engine.detect_version_conflicts()
    assert len(conflicts) == 1
    assert conflicts[0]["package"] == "requests"
    assert len(conflicts[0]["versions"]) == 2


def test_detect_no_version_conflicts(engine):
    engine.register_dependency("requests", version="2.31.0", server_id="mcp-1")
    engine.register_dependency("flask", version="3.0.0", server_id="mcp-1")
    conflicts = engine.detect_version_conflicts()
    assert len(conflicts) == 0


def test_generate_report(engine):
    engine.register_dependency("lib-a", server_id="mcp-1")
    engine.scan_dependencies()
    report = engine.generate_report()
    assert isinstance(report, DependencyScanReport)
    assert report.total_dependencies == 1
    assert report.total_scans == 1


def test_get_stats(engine):
    engine.register_dependency("lib-a", server_id="mcp-1")
    stats = engine.get_stats()
    assert "total_dependencies" in stats
    assert "total_scans" in stats
    assert "unique_packages" in stats
    assert "unique_servers" in stats


def test_clear_data(engine):
    engine.register_dependency("lib-a")
    engine.scan_dependencies()
    engine.clear_data()
    assert len(engine._dependencies) == 0
    assert len(engine._scans) == 0
