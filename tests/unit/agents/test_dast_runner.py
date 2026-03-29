"""Tests for shieldops.agents.dast_runner — dynamic application security testing."""

from __future__ import annotations

import pytest

from shieldops.agents.dast_runner.models import (
    AttackType,
    CrawlResult,
    DASTRunnerState,
    DASTStage,
    EndpointFinding,
    ScanScope,
)


def _state(**kw) -> DASTRunnerState:
    return DASTRunnerState(**kw)


class TestEnums:
    def test_dast_stage_values(self):
        assert DASTStage.DISCOVER_ENDPOINTS == "discover_endpoints"
        assert DASTStage.CRAWL_APPLICATION == "crawl_application"
        assert DASTStage.TEST_AUTHENTICATION == "test_authentication"
        assert DASTStage.FUZZ_PARAMETERS == "fuzz_parameters"
        assert DASTStage.ANALYZE_RESPONSES == "analyze_responses"
        assert DASTStage.REPORT == "report"

    def test_attack_type_values(self):
        assert AttackType.AUTH_BYPASS == "auth_bypass"
        assert AttackType.IDOR == "idor"
        assert AttackType.SSRF == "ssrf"
        assert AttackType.SQLI == "sqli"

    def test_scan_scope_values(self):
        assert ScanScope.FULL == "full"
        assert ScanScope.AUTH_ONLY == "auth_only"
        assert ScanScope.API_ONLY == "api_only"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == DASTStage.DISCOVER_ENDPOINTS
        assert s.target_url == ""
        assert s.scan_scope == ScanScope.FULL
        assert s.crawl_results == []
        assert s.total_endpoints == 0
        assert s.all_findings == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(target_url="https://example.com", total_endpoints=5)
        assert s.target_url == "https://example.com"
        assert s.total_endpoints == 5

    def test_crawl_result_defaults(self):
        c = CrawlResult()
        assert c.url == ""
        assert c.method == "GET"
        assert c.status_code == 0
        assert c.has_auth is False

    def test_endpoint_finding_defaults(self):
        f = EndpointFinding()
        assert f.id == ""
        assert f.attack_type == AttackType.SQLI
        assert f.severity == "medium"
        assert f.confidence == 0.0
        assert f.is_confirmed is False


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.dast_runner.tools import DASTRunnerToolkit

        return DASTRunnerToolkit()

    @pytest.mark.asyncio()
    async def test_discover_endpoints(self, toolkit):
        results = await toolkit.discover_endpoints("http://localhost", ScanScope.FULL)
        assert isinstance(results, list)
        assert len(results) >= 4

    @pytest.mark.asyncio()
    async def test_test_authentication(self, toolkit):
        eps = await toolkit.discover_endpoints("http://localhost", ScanScope.FULL)
        findings = await toolkit.test_authentication(eps)
        assert isinstance(findings, list)
        assert all(isinstance(f, EndpointFinding) for f in findings)

    @pytest.mark.asyncio()
    async def test_fuzz_parameters(self, toolkit):
        eps = await toolkit.discover_endpoints("http://localhost", ScanScope.FULL)
        findings = await toolkit.fuzz_parameters(eps)
        assert isinstance(findings, list)

    @pytest.mark.asyncio()
    async def test_analyze_responses(self, toolkit):
        result = await toolkit.analyze_responses([], [])
        assert isinstance(result, list)
        assert len(result) == 0


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.dast_runner.graph import create_dast_runner_graph

        sg = create_dast_runner_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.dast_runner.graph import create_dast_runner_graph

        sg = create_dast_runner_graph()
        compiled = sg.compile()
        assert compiled is not None
