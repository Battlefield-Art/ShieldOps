"""Tests for shieldops.agents.cnapp_analyzer."""

from __future__ import annotations

import pytest

from shieldops.agents.cnapp_analyzer.models import (
    CNAPPAnalyzerState,
    CNAPPStage,
    CodeVulnerability,
    ComplianceFramework,
    EntitlementRisk,
    PostureFinding,
    SecurityDomain,
    SeverityLevel,
    UnifiedRiskScore,
    WorkloadThreat,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_cnapp_stage_values(self) -> None:
        assert CNAPPStage.SCAN_CLOUD_POSTURE == "scan_cloud_posture"
        assert CNAPPStage.ASSESS_WORKLOAD_PROTECTION == "assess_workload_protection"
        assert CNAPPStage.ANALYZE_IDENTITY_ENTITLEMENTS == "analyze_identity_entitlements"
        assert CNAPPStage.SCAN_CODE_SECURITY == "scan_code_security"
        assert CNAPPStage.CORRELATE_RISKS == "correlate_risks"
        assert CNAPPStage.REPORT == "report"
        assert len(CNAPPStage) == 6

    def test_security_domain_values(self) -> None:
        assert SecurityDomain.CSPM == "cspm"
        assert SecurityDomain.CWPP == "cwpp"
        assert SecurityDomain.CIEM == "ciem"
        assert SecurityDomain.CODE_SECURITY == "code_security"
        assert SecurityDomain.DATA_SECURITY == "data_security"
        assert len(SecurityDomain) == 5

    def test_compliance_framework_values(self) -> None:
        assert ComplianceFramework.CIS == "cis"
        assert ComplianceFramework.NIST == "nist"
        assert ComplianceFramework.SOC2 == "soc2"
        assert ComplianceFramework.PCI_DSS == "pci_dss"
        assert ComplianceFramework.HIPAA == "hipaa"
        assert ComplianceFramework.ISO27001 == "iso27001"
        assert len(ComplianceFramework) == 6

    def test_severity_level_values(self) -> None:
        assert SeverityLevel.CRITICAL == "critical"
        assert SeverityLevel.HIGH == "high"
        assert SeverityLevel.MEDIUM == "medium"
        assert SeverityLevel.LOW == "low"
        assert SeverityLevel.INFO == "info"
        assert len(SeverityLevel) == 5


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = CNAPPAnalyzerState()
        assert state.request_id == ""
        assert state.stage == CNAPPStage.SCAN_CLOUD_POSTURE
        assert state.tenant_id == ""
        assert state.providers == []
        assert state.frameworks == []
        assert state.posture_findings == []
        assert state.workload_threats == []
        assert state.entitlement_risks == []
        assert state.code_vulns == []
        assert state.unified_risk_score == {}
        assert state.error == ""

    def test_posture_finding_defaults(self) -> None:
        pf = PostureFinding()
        assert pf.status == "pass"
        assert pf.severity == SeverityLevel.MEDIUM
        assert pf.auto_remediable is False
        assert 0.0 <= pf.risk_score <= 100.0

    def test_workload_threat_defaults(self) -> None:
        wt = WorkloadThreat()
        assert wt.severity == SeverityLevel.MEDIUM
        assert wt.cvss_score == 0.0
        assert wt.fix_available is False
        assert wt.runtime_detected is False

    def test_entitlement_risk_defaults(self) -> None:
        er = EntitlementRisk()
        assert er.permission_count == 0
        assert er.unused_ratio == 0.0

    def test_code_vulnerability_defaults(self) -> None:
        cv = CodeVulnerability()
        assert cv.line_number == 0
        assert cv.severity == SeverityLevel.MEDIUM
        assert cv.cwe_id == ""

    def test_unified_risk_score_defaults(self) -> None:
        urs = UnifiedRiskScore()
        assert urs.overall_score == 0.0
        assert urs.risk_level == "medium"
        assert urs.attack_paths == []
        assert urs.top_recommendations == []


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.cnapp_analyzer.tools import CNAPPAnalyzerToolkit

        return CNAPPAnalyzerToolkit()

    @pytest.mark.asyncio
    async def test_scan_cloud_posture_aws(self, toolkit) -> None:
        findings = await toolkit.scan_cloud_posture(["aws"])
        assert isinstance(findings, list)
        assert len(findings) >= 1
        assert all("control_id" in f for f in findings)

    @pytest.mark.asyncio
    async def test_scan_cloud_posture_multi_provider(self, toolkit) -> None:
        findings = await toolkit.scan_cloud_posture(["aws", "gcp"])
        providers = {f.get("provider") for f in findings}
        assert "aws" in providers
        assert "gcp" in providers

    @pytest.mark.asyncio
    async def test_assess_workload_protection(self, toolkit) -> None:
        threats = await toolkit.assess_workload_protection()
        assert isinstance(threats, list)
        assert len(threats) >= 1

    @pytest.mark.asyncio
    async def test_analyze_identity_entitlements(self, toolkit) -> None:
        risks = await toolkit.analyze_identity_entitlements()
        assert isinstance(risks, list)
        assert len(risks) >= 1

    @pytest.mark.asyncio
    async def test_scan_code_security(self, toolkit) -> None:
        vulns = await toolkit.scan_code_security()
        assert isinstance(vulns, list)
        assert len(vulns) >= 1

    @pytest.mark.asyncio
    async def test_correlate_risks(self, toolkit) -> None:
        posture = [{"severity": "critical", "auto_remediable": True}]
        workload = [{"severity": "high", "cvss_score": 9.0}]
        entitlement = [{"severity": "high", "unused_ratio": 0.9}]
        code = [{"severity": "medium"}]
        result = await toolkit.correlate_risks(posture, workload, entitlement, code)
        assert "overall_score" in result
        assert "risk_level" in result


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.cnapp_analyzer.graph import build_graph
        from shieldops.agents.cnapp_analyzer.tools import CNAPPAnalyzerToolkit

        toolkit = CNAPPAnalyzerToolkit()
        graph = build_graph(toolkit)
        compiled = graph.compile()
        assert compiled is not None

    def test_create_factory(self) -> None:
        from shieldops.agents.cnapp_analyzer.graph import create_cnapp_analyzer_graph

        graph = create_cnapp_analyzer_graph()
        compiled = graph.compile()
        assert compiled is not None
