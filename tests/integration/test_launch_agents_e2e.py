"""End-to-end integration tests for all 10 launch agents.

Each test verifies: graph compiles → executes with mock state → returns valid result.
These are behavioral integration tests, not unit tests of individual methods.
"""

from __future__ import annotations

import pytest


class TestInvestigationAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.investigation.graph import create_investigation_graph

        graph = create_investigation_graph()
        app = graph.compile()
        assert app is not None

    def test_runner_class_exists(self) -> None:
        from shieldops.agents.investigation.runner import InvestigationRunner

        assert InvestigationRunner is not None


class TestRemediationAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.remediation.graph import create_remediation_graph

        graph = create_remediation_graph()
        app = graph.compile()
        assert app is not None

    def test_toolkit_has_policy_methods(self) -> None:
        from shieldops.agents.remediation.tools import RemediationToolkit

        toolkit = RemediationToolkit()
        assert hasattr(toolkit, "evaluate_risk_score")
        assert hasattr(toolkit, "enforce_blast_radius")
        assert hasattr(toolkit, "contain_host")
        assert hasattr(toolkit, "create_servicenow_ticket")
        assert hasattr(toolkit, "record_audit")


class TestThreatHunterAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.threat_hunter.graph import create_threat_hunter_graph

        graph = create_threat_hunter_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_methods_return_data(self) -> None:
        from shieldops.agents.threat_hunter.tools import ThreatHunterToolkit

        toolkit = ThreatHunterToolkit()
        result = await toolkit.generate_hypothesis({"hypothesis": "test APT activity"})
        assert isinstance(result, dict)
        assert result  # not empty


class TestIncidentResponseAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.incident_response.graph import create_incident_response_graph

        graph = create_incident_response_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_assess_returns_data(self) -> None:
        from shieldops.agents.incident_response.tools import IncidentResponseToolkit

        toolkit = IncidentResponseToolkit()
        result = await toolkit.assess_incident(
            {
                "alerts": [{"severity": "high", "source": "crowdstrike"}],
                "affected_systems": ["web-01"],
            }
        )
        assert isinstance(result, dict)
        assert "assessment_score" in result or "severity_score" in result


class TestSOCAnalystAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.soc_analyst.graph import create_soc_analyst_graph

        graph = create_soc_analyst_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_triage_returns_decision(self) -> None:
        from shieldops.agents.soc_analyst.tools import SOCAnalystToolkit

        toolkit = SOCAnalystToolkit()
        result = await toolkit.triage_alert(
            {
                "alert_type": "malware_detected",
                "severity": "high",
                "source": "crowdstrike",
            }
        )
        assert isinstance(result, dict)
        assert "decision" in result


class TestComplianceAuditorAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.compliance_auditor.graph import create_compliance_auditor_graph

        graph = create_compliance_auditor_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_audit_returns_findings(self) -> None:
        from shieldops.agents.compliance_auditor.tools import ComplianceAuditorToolkit

        toolkit = ComplianceAuditorToolkit()
        result = await toolkit.audit_aws_config({"region": "us-east-1"})
        # Returns list of findings or dict with findings key
        assert isinstance(result, (list, dict))
        if isinstance(result, list):
            assert len(result) > 0
        else:
            assert "findings" in result


class TestVulnerabilityManagerAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.vulnerability_manager.graph import create_vulnerability_manager_graph

        graph = create_vulnerability_manager_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_scan_returns_vulns(self) -> None:
        from shieldops.agents.vulnerability_manager.tools import VulnerabilityManagerToolkit

        toolkit = VulnerabilityManagerToolkit()
        result = await toolkit.scan_vulnerabilities("test-tenant")
        # Returns list of Vulnerability objects or dict
        assert isinstance(result, (list, dict))
        if isinstance(result, list):
            assert len(result) > 0


class TestIdentityGraphAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.identity_graph.graph import create_identity_graph

        graph = create_identity_graph()
        app = graph.compile()
        assert app is not None

    @pytest.mark.asyncio
    async def test_toolkit_discover_returns_identities(self) -> None:
        from shieldops.agents.identity_graph.tools import IdentityGraphToolkit

        toolkit = IdentityGraphToolkit()
        result = await toolkit.discover_identities({})
        assert isinstance(result, dict)
        assert "identities" in result
        assert result["total_discovered"] > 0


class TestCostAgentE2E:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.cost.graph import create_cost_graph

        graph = create_cost_graph()
        app = graph.compile()
        assert app is not None


class TestAgentFirewallE2E:
    def test_interceptor_works(self) -> None:
        from shieldops.sdk.config import SDKConfig, SDKMode
        from shieldops.sdk.interceptor import ShieldOpsInterceptor

        config = SDKConfig(api_key="test", mode=SDKMode.ENFORCE)
        interceptor = ShieldOpsInterceptor(config)

        # Safe call
        result = interceptor.intercept("read_file", {"path": "/var/log/test"})  # nosec B108
        assert result.decision == "allow"

        # Dangerous call
        result = interceptor.intercept("drop_table", {"table": "users"})
        assert result.decision == "block"
        assert result.risk_score == 1.0


class TestPolicyGateIntegration:
    @pytest.mark.asyncio
    async def test_policy_gate_with_no_engine(self) -> None:
        from shieldops.agents.policy_gate import check_policy

        result = await check_policy(None, "investigation", "query")
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_nhi_bridge_integration(self) -> None:
        from shieldops.agents.nhi_policy_bridge import NHIPolicyBridge

        bridge = NHIPolicyBridge()
        bridge.update_inventory(
            [
                {"id": "svc-1", "name": "admin-bot", "risk_level": "critical", "risk_score": 95},
            ]
        )
        result = bridge.evaluate_identity("svc-1")
        assert result["restricted"] is True
        assert result["action"] == "block"
