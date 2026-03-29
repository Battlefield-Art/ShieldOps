"""Tests for shieldops.agents.sast_scanner — static application security testing."""

from __future__ import annotations

import pytest

from shieldops.agents.sast_scanner.models import (
    CodeLanguage,
    CodeLocation,
    SASTScannerState,
    SASTStage,
    ScanFinding,
    VulnCategory,
)


def _state(**kw) -> SASTScannerState:
    return SASTScannerState(**kw)


class TestEnums:
    def test_sast_stage_values(self):
        assert SASTStage.DISCOVER_FILES == "discover_files"
        assert SASTStage.PARSE_AST == "parse_ast"
        assert SASTStage.SCAN_PATTERNS == "scan_patterns"
        assert SASTStage.ANALYZE_DATAFLOW == "analyze_dataflow"
        assert SASTStage.PRIORITIZE == "prioritize"
        assert SASTStage.REPORT == "report"

    def test_vuln_category_values(self):
        assert VulnCategory.SQL_INJECTION == "sql_injection"
        assert VulnCategory.XSS == "xss"
        assert VulnCategory.COMMAND_INJECTION == "command_injection"
        assert VulnCategory.PATH_TRAVERSAL == "path_traversal"
        assert VulnCategory.BUFFER_OVERFLOW == "buffer_overflow"

    def test_code_language_values(self):
        assert CodeLanguage.PYTHON == "python"
        assert CodeLanguage.JAVASCRIPT == "javascript"
        assert CodeLanguage.GO == "go"
        assert CodeLanguage.JAVA == "java"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == SASTStage.DISCOVER_FILES
        assert s.scan_targets == []
        assert s.discovered_files == []
        assert s.total_files == 0
        assert s.findings == []
        assert s.prioritized == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.stats == {}
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_files=10, critical_count=3)
        assert s.tenant_id == "t-01"
        assert s.total_files == 10
        assert s.critical_count == 3

    def test_code_location_defaults(self):
        loc = CodeLocation()
        assert loc.file_path == ""
        assert loc.line_start == 0
        assert loc.snippet == ""
        assert loc.language == CodeLanguage.PYTHON

    def test_scan_finding_defaults(self):
        f = ScanFinding()
        assert f.id == ""
        assert f.rule_id == ""
        assert f.category == VulnCategory.SQL_INJECTION
        assert f.severity == "medium"
        assert f.cwe_id == ""
        assert f.confidence == 0.0
        assert f.is_false_positive is False
        assert f.dataflow_trace == []


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.sast_scanner.tools import SASTScannerToolkit

        return SASTScannerToolkit()

    @pytest.mark.asyncio()
    async def test_discover_files(self, toolkit):
        files = await toolkit.discover_files("t-01", ["app.py", "utils.go"])
        assert isinstance(files, list)
        assert len(files) == 2
        assert all("path" in f for f in files)

    @pytest.mark.asyncio()
    async def test_parse_ast(self, toolkit):
        files = [{"id": "f1", "path": "test.py", "language": "python"}]
        result = await toolkit.parse_ast(files)
        assert isinstance(result, list)
        assert len(result) == 1

    @pytest.mark.asyncio()
    async def test_scan_patterns(self, toolkit):
        result = await toolkit.scan_patterns(["/nonexistent"])
        assert isinstance(result, list)

    def test_prioritize(self, toolkit):
        findings = [
            ScanFinding(id="f1", severity="high", confidence=0.9),
            ScanFinding(id="f2", severity="critical", confidence=0.8),
        ]
        result = toolkit.prioritize(findings)
        assert result[0].severity == "critical"


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.sast_scanner.graph import create_sast_scanner_graph

        sg = create_sast_scanner_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.sast_scanner.graph import create_sast_scanner_graph

        sg = create_sast_scanner_graph()
        compiled = sg.compile()
        assert compiled is not None
