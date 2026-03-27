"""Tests for shieldops.agents.security_testing."""

from __future__ import annotations

from shieldops.agents.security_testing.models import (
    FindingSeverity,
    SecurityTestingState,
    TestCategory,
    TestStage,
)


class TestEnums:
    def test_teststage_scope(self):
        assert TestStage.SCOPE == "scope"

    def test_teststage_scan(self):
        assert TestStage.SCAN == "scan"

    def test_teststage_analyze(self):
        assert TestStage.ANALYZE == "analyze"

    def test_teststage_report(self):
        assert TestStage.REPORT == "report"

    def test_testcategory_vulnerability(self):
        assert TestCategory.VULNERABILITY == "vulnerability"

    def test_testcategory_configuration(self):
        assert TestCategory.CONFIGURATION == "configuration"

    def test_testcategory_network(self):
        assert TestCategory.NETWORK == "network"

    def test_testcategory_credential(self):
        assert TestCategory.CREDENTIAL == "credential"

    def test_findingseverity_critical(self):
        assert FindingSeverity.CRITICAL == "critical"

    def test_findingseverity_high(self):
        assert FindingSeverity.HIGH == "high"

    def test_findingseverity_medium(self):
        assert FindingSeverity.MEDIUM == "medium"

    def test_findingseverity_low(self):
        assert FindingSeverity.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = SecurityTestingState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security_testing.graph import (
            create_security_testing_graph,
        )

        sg = create_security_testing_graph()
        assert sg.compile() is not None
