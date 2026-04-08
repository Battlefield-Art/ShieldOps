"""Unit tests for the Automated Security Testing Agent."""

from __future__ import annotations

import pytest

from shieldops.agents.security_testing.agent import SecurityTestingRunner
from shieldops.agents.security_testing.graph import (
    build_graph,
    create_security_testing_graph,
)
from shieldops.agents.security_testing.models import (
    FindingSeverity,
    SecurityFinding,
    SecurityTestingState,
    TestCategory,
    TestReport,
    TestScope,
    TestStage,
)
from shieldops.agents.security_testing.nodes import (
    analyze_findings,
    define_scope,
    execute_scans,
    generate_report,
)
from shieldops.agents.security_testing.prompts import (
    SYSTEM_ANALYZE_FINDINGS,
    SYSTEM_DEFINE_SCOPE,
    SYSTEM_EXECUTE_SCANS,
    SYSTEM_GENERATE_REPORT,
)
from shieldops.agents.security_testing.tools import SecurityTestingToolkit

# =====================================================================
# Enum Tests
# =====================================================================


class TestTestStage:
    """Tests for TestStage enum."""

    def test_enum_values(self) -> None:
        assert TestStage.SCOPE == "scope"
        assert TestStage.SCAN == "scan"
        assert TestStage.ANALYZE == "analyze"
        assert TestStage.REPORT == "report"

    def test_enum_membership(self) -> None:
        assert len(TestStage) == 4

    def test_string_comparison(self) -> None:
        assert TestStage("scope") is TestStage.SCOPE


class TestTestCategory:
    """Tests for TestCategory enum."""

    def test_enum_values(self) -> None:
        assert TestCategory.VULNERABILITY == "vulnerability"
        assert TestCategory.CONFIGURATION == "configuration"
        assert TestCategory.NETWORK == "network"
        assert TestCategory.CREDENTIAL == "credential"
        assert TestCategory.COMPLIANCE == "compliance"

    def test_enum_membership(self) -> None:
        assert len(TestCategory) == 5


class TestFindingSeverity:
    """Tests for FindingSeverity enum."""

    def test_enum_values(self) -> None:
        assert FindingSeverity.CRITICAL == "critical"
        assert FindingSeverity.HIGH == "high"
        assert FindingSeverity.MEDIUM == "medium"
        assert FindingSeverity.LOW == "low"
        assert FindingSeverity.INFO == "info"

    def test_enum_membership(self) -> None:
        assert len(FindingSeverity) == 5


# =====================================================================
# Model Tests
# =====================================================================


class TestTestScope:
    """Tests for TestScope model."""

    def test_defaults(self) -> None:
        scope = TestScope()
        assert scope.targets == []
        assert scope.categories == []
        assert scope.exclusions == []

    def test_creation_with_values(self) -> None:
        scope = TestScope(
            targets=["server-01", "server-02"],
            categories=[TestCategory.VULNERABILITY, TestCategory.CONFIGURATION],
            exclusions=["server-03"],
        )
        assert len(scope.targets) == 2
        assert len(scope.categories) == 2
        assert "server-03" in scope.exclusions


class TestSecurityFinding:
    """Tests for SecurityFinding model."""

    def test_defaults(self) -> None:
        finding = SecurityFinding()
        assert finding.finding_id == ""
        assert finding.category == TestCategory.VULNERABILITY
        assert finding.severity == FindingSeverity.MEDIUM
        assert finding.risk_score == 0
        assert finding.cve_id == ""

    def test_creation_with_values(self) -> None:
        finding = SecurityFinding(
            finding_id="f001",
            category=TestCategory.CREDENTIAL,
            severity=FindingSeverity.CRITICAL,
            title="Exposed API Key",
            description="API key found in logs",
            affected_resource="app-server-01",
            remediation="Rotate key and use secret manager",
            risk_score=90,
            cve_id="",
        )
        assert finding.finding_id == "f001"
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.risk_score == 90

    def test_model_dump(self) -> None:
        finding = SecurityFinding(finding_id="f002", title="Test")
        d = finding.model_dump()
        assert d["finding_id"] == "f002"
        assert d["category"] == "vulnerability"


class TestTestReport:
    """Tests for TestReport model."""

    def test_defaults(self) -> None:
        report = TestReport()
        assert report.findings == []
        assert report.critical_count == 0
        assert report.high_count == 0
        assert report.risk_score_total == 0
        assert report.pass_rate == 0.0

    def test_creation_with_values(self) -> None:
        finding = SecurityFinding(
            finding_id="f001",
            severity=FindingSeverity.CRITICAL,
            risk_score=90,
        )
        report = TestReport(
            scope=TestScope(targets=["server-01"]),
            findings=[finding],
            critical_count=1,
            high_count=0,
            risk_score_total=90,
            pass_rate=0.0,
        )
        assert report.critical_count == 1
        assert report.risk_score_total == 90


class TestSecurityTestingState:
    """Tests for SecurityTestingState model."""

    def test_defaults(self) -> None:
        state = SecurityTestingState()
        assert state.request_id == ""
        assert state.stage == TestStage.SCOPE
        assert state.scope == {}
        assert state.findings == []
        assert state.report == {}
        assert state.recommendations == []
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_model_dump_roundtrip(self) -> None:
        state = SecurityTestingState(request_id="req-1")
        d = state.model_dump()
        restored = SecurityTestingState(**d)
        assert restored.request_id == "req-1"


# =====================================================================
# Toolkit Tests
# =====================================================================


class TestSecurityTestingToolkit:
    """Tests for SecurityTestingToolkit."""

    @pytest.fixture()
    def toolkit(self) -> SecurityTestingToolkit:
        return SecurityTestingToolkit()

    @pytest.mark.asyncio()
    async def test_define_scope(self, toolkit: SecurityTestingToolkit) -> None:
        scope = await toolkit.define_scope(
            targets=["server-01", "server-02"],
            categories=[TestCategory.VULNERABILITY, TestCategory.CONFIGURATION],
            exclusions=["server-03"],
        )
        assert isinstance(scope, TestScope)
        assert len(scope.targets) == 2
        assert len(scope.categories) == 2
        assert "server-03" in scope.exclusions

    @pytest.mark.asyncio()
    async def test_define_scope_defaults(self, toolkit: SecurityTestingToolkit) -> None:
        scope = await toolkit.define_scope(
            targets=["server-01"],
            categories=[],
        )
        assert isinstance(scope, TestScope)
        # Empty categories get expanded to all categories
        assert len(scope.categories) == len(TestCategory)

    @pytest.mark.asyncio()
    async def test_run_vulnerability_scan(self, toolkit: SecurityTestingToolkit) -> None:
        findings = await toolkit.run_vulnerability_scan("app-server-01")
        assert isinstance(findings, list)
        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SecurityFinding)
            assert f.category == TestCategory.VULNERABILITY
            assert f.finding_id != ""
            assert f.affected_resource == "app-server-01"

    @pytest.mark.asyncio()
    async def test_run_config_audit(self, toolkit: SecurityTestingToolkit) -> None:
        findings = await toolkit.run_config_audit("web-server-01")
        assert isinstance(findings, list)
        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SecurityFinding)
            assert f.category == TestCategory.CONFIGURATION
            assert f.remediation != ""

    @pytest.mark.asyncio()
    async def test_run_credential_check(self, toolkit: SecurityTestingToolkit) -> None:
        findings = await toolkit.run_credential_check("db-server-01")
        assert isinstance(findings, list)
        assert len(findings) >= 1
        for f in findings:
            assert isinstance(f, SecurityFinding)
            assert f.category == TestCategory.CREDENTIAL

    @pytest.mark.asyncio()
    async def test_generate_report(self, toolkit: SecurityTestingToolkit) -> None:
        findings = [
            SecurityFinding(
                finding_id="f001",
                severity=FindingSeverity.CRITICAL,
                title="Critical Vuln",
                affected_resource="server-01",
                risk_score=95,
            ),
            SecurityFinding(
                finding_id="f002",
                severity=FindingSeverity.LOW,
                title="Low Info",
                affected_resource="server-02",
                risk_score=15,
            ),
        ]
        scope = TestScope(targets=["server-01", "server-02"])
        report = await toolkit.generate_report(findings, scope)
        assert isinstance(report, TestReport)
        assert report.critical_count == 1
        assert report.high_count == 0
        assert report.risk_score_total == 110
        # Findings sorted by risk score descending
        assert report.findings[0].risk_score >= report.findings[-1].risk_score

    @pytest.mark.asyncio()
    async def test_generate_report_pass_rate(self, toolkit: SecurityTestingToolkit) -> None:
        findings = [
            SecurityFinding(
                finding_id="f001",
                severity=FindingSeverity.LOW,
                title="Minor Issue",
                affected_resource="server-01",
                risk_score=10,
            ),
        ]
        scope = TestScope(targets=["server-01", "server-02"])
        report = await toolkit.generate_report(findings, scope)
        # server-01 has only LOW finding, so both targets pass
        assert report.pass_rate == 1.0


# =====================================================================
# Node Tests
# =====================================================================


class TestNodes:
    """Tests for node functions."""

    @pytest.fixture()
    def toolkit(self) -> SecurityTestingToolkit:
        return SecurityTestingToolkit()

    @pytest.mark.asyncio()
    async def test_define_scope_node(self, toolkit: SecurityTestingToolkit) -> None:
        state: dict = {"request_id": "test", "reasoning_chain": []}
        result = await define_scope(state, toolkit)
        assert result["stage"] == TestStage.SCAN.value
        assert "scope" in result
        assert isinstance(result["scope"], dict)
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio()
    async def test_execute_scans_node(self, toolkit: SecurityTestingToolkit) -> None:
        scope = TestScope(
            targets=["server-01"],
            categories=[TestCategory.VULNERABILITY],
        )
        state: dict = {
            "scope": scope.model_dump(),
            "reasoning_chain": [],
        }
        result = await execute_scans(state, toolkit)
        assert result["stage"] == TestStage.ANALYZE.value
        assert isinstance(result["findings"], list)
        assert len(result["findings"]) >= 1

    @pytest.mark.asyncio()
    async def test_analyze_findings_node(self, toolkit: SecurityTestingToolkit) -> None:
        findings = [
            SecurityFinding(
                finding_id="f001",
                severity=FindingSeverity.CRITICAL,
                title="Critical Vuln",
                affected_resource="server-01",
                remediation="Patch immediately",
                risk_score=90,
            ).model_dump(),
            SecurityFinding(
                finding_id="f002",
                severity=FindingSeverity.CRITICAL,
                title="Critical Vuln",
                affected_resource="server-01",
                remediation="Patch immediately",
                risk_score=90,
            ).model_dump(),
        ]
        state: dict = {"findings": findings, "reasoning_chain": []}
        result = await analyze_findings(state, toolkit)
        assert result["stage"] == TestStage.REPORT.value
        # Should deduplicate: 2 identical findings -> 1
        assert len(result["findings"]) == 1
        assert len(result["recommendations"]) >= 1

    @pytest.mark.asyncio()
    async def test_generate_report_node(self, toolkit: SecurityTestingToolkit) -> None:
        finding = SecurityFinding(
            finding_id="f001",
            severity=FindingSeverity.HIGH,
            title="High Vuln",
            affected_resource="server-01",
            risk_score=75,
        )
        scope = TestScope(targets=["server-01"])
        state: dict = {
            "findings": [finding.model_dump()],
            "scope": scope.model_dump(),
            "reasoning_chain": [],
        }
        result = await generate_report(state, toolkit)
        assert result["stage"] == TestStage.REPORT.value
        assert "report" in result
        assert result["report"]["high_count"] == 1


# =====================================================================
# Graph Tests
# =====================================================================


class TestGraph:
    """Tests for graph construction."""

    def test_build_graph(self) -> None:
        toolkit = SecurityTestingToolkit()
        graph = build_graph(toolkit)
        assert graph is not None

    def test_create_security_testing_graph(self) -> None:
        graph = create_security_testing_graph()
        assert graph is not None


# =====================================================================
# Prompt Tests
# =====================================================================


class TestPrompts:
    """Tests for prompt templates."""

    def test_prompts_are_strings(self) -> None:
        assert isinstance(SYSTEM_DEFINE_SCOPE, str)
        assert isinstance(SYSTEM_EXECUTE_SCANS, str)
        assert isinstance(SYSTEM_ANALYZE_FINDINGS, str)
        assert isinstance(SYSTEM_GENERATE_REPORT, str)

    def test_prompts_are_nonempty(self) -> None:
        assert len(SYSTEM_DEFINE_SCOPE) > 50
        assert len(SYSTEM_EXECUTE_SCANS) > 50
        assert len(SYSTEM_ANALYZE_FINDINGS) > 50
        assert len(SYSTEM_GENERATE_REPORT) > 50


# =====================================================================
# Runner Tests
# =====================================================================


class TestSecurityTestingRunner:
    """Tests for SecurityTestingRunner."""

    def test_runner_init(self) -> None:
        runner = SecurityTestingRunner()
        assert runner._toolkit is not None
        assert runner._app is not None

    @pytest.mark.asyncio()
    async def test_runner_run(self) -> None:
        runner = SecurityTestingRunner()
        result = await runner.run(request_id="test-run-001")
        assert isinstance(result, dict)
        assert "reasoning_chain" in result

    @pytest.mark.asyncio()
    async def test_runner_run_with_targets(self) -> None:
        runner = SecurityTestingRunner()
        result = await runner.run(
            request_id="test-run-002",
            targets=["web-01"],
            categories=["vulnerability"],
        )
        assert isinstance(result, dict)
        assert "report" in result
