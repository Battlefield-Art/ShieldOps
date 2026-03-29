"""Tests for shieldops.agents.iac_security_scanner — IaC security scanning."""

from __future__ import annotations

import pytest

from shieldops.agents.iac_security_scanner.models import (
    IACProvider,
    IACResource,
    IACScannerState,
    IACScanStage,
    MisconfigSeverity,
    Misconfiguration,
)


def _state(**kw) -> IACScannerState:
    return IACScannerState(**kw)


class TestEnums:
    def test_iac_scan_stage_values(self):
        assert IACScanStage.DISCOVER_TEMPLATES == "discover_templates"
        assert IACScanStage.PARSE_RESOURCES == "parse_resources"
        assert IACScanStage.SCAN_MISCONFIGS == "scan_misconfigs"
        assert IACScanStage.EVALUATE_POLICIES == "evaluate_policies"
        assert IACScanStage.PRIORITIZE == "prioritize"
        assert IACScanStage.REPORT == "report"

    def test_iac_provider_values(self):
        assert IACProvider.TERRAFORM == "terraform"
        assert IACProvider.CLOUDFORMATION == "cloudformation"
        assert IACProvider.KUBERNETES == "kubernetes"
        assert IACProvider.HELM == "helm"

    def test_misconfig_severity_values(self):
        assert MisconfigSeverity.CRITICAL == "critical"
        assert MisconfigSeverity.HIGH == "high"
        assert MisconfigSeverity.INFO == "info"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == IACScanStage.DISCOVER_TEMPLATES
        assert s.scan_targets == []
        assert s.discovered_templates == []
        assert s.total_templates == 0
        assert s.resources == []
        assert s.misconfigurations == []
        assert s.policy_violations == []
        assert s.prioritized == []
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_templates=8)
        assert s.tenant_id == "t-01"
        assert s.total_templates == 8

    def test_iac_resource_defaults(self):
        r = IACResource()
        assert r.id == ""
        assert r.resource_type == ""
        assert r.provider == IACProvider.TERRAFORM
        assert r.is_public is False
        assert r.is_encrypted is True
        assert r.has_logging is True

    def test_misconfiguration_defaults(self):
        m = Misconfiguration()
        assert m.id == ""
        assert m.severity == MisconfigSeverity.MEDIUM
        assert m.cis_benchmark == ""
        assert m.is_auto_fixable is False


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.iac_security_scanner.tools import IACSecurityScannerToolkit

        return IACSecurityScannerToolkit()

    @pytest.mark.asyncio()
    async def test_discover_templates(self, toolkit):
        templates = await toolkit.discover_templates("t-01", ["main.tf"])
        assert isinstance(templates, list)
        assert len(templates) == 1

    @pytest.mark.asyncio()
    async def test_parse_resources(self, toolkit):
        templates = [{"id": "t1", "path": "main.tf", "provider": "terraform"}]
        resources = await toolkit.parse_resources(templates, [])
        assert isinstance(resources, list)
        assert len(resources) >= 1

    @pytest.mark.asyncio()
    async def test_scan_misconfigs(self, toolkit):
        result = await toolkit.scan_misconfigs([], ["/nonexistent"])
        assert isinstance(result, list)

    @pytest.mark.asyncio()
    async def test_evaluate_policies(self, toolkit):
        misconfigs = [
            Misconfiguration(id="m1", severity=MisconfigSeverity.CRITICAL, rule_id="IAC-001")
        ]
        violations = await toolkit.evaluate_policies(misconfigs, [])
        assert isinstance(violations, list)
        assert len(violations) >= 1


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.iac_security_scanner.graph import create_iac_security_scanner_graph

        sg = create_iac_security_scanner_graph()
        assert sg.compile() is not None
