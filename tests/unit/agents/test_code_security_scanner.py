"""Tests for shieldops.agents.code_security_scanner."""

from __future__ import annotations

from shieldops.agents.code_security_scanner.models import (
    CodeSecurityScannerState,
    FindingSeverity,
    ScanStage,
    ScanTarget,
)


class TestEnums:
    def test_scanstage_discover_repositories(self):
        assert ScanStage.DISCOVER_REPOSITORIES == "discover_repositories"

    def test_scanstage_scan_iac(self):
        assert ScanStage.SCAN_IAC == "scan_iac"

    def test_scanstage_scan_dependencies(self):
        assert ScanStage.SCAN_DEPENDENCIES == "scan_dependencies"

    def test_scanstage_scan_application_code(self):
        assert ScanStage.SCAN_APPLICATION_CODE == "scan_application_code"

    def test_scantarget_terraform(self):
        assert ScanTarget.TERRAFORM == "terraform"

    def test_scantarget_cloudformation(self):
        assert ScanTarget.CLOUDFORMATION == "cloudformation"

    def test_scantarget_kubernetes_yaml(self):
        assert ScanTarget.KUBERNETES_YAML == "kubernetes_yaml"

    def test_scantarget_dockerfile(self):
        assert ScanTarget.DOCKERFILE == "dockerfile"

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
        s = CodeSecurityScannerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.code_security_scanner.graph import (
            create_code_security_scanner_graph,
        )

        sg = create_code_security_scanner_graph()
        assert sg.compile() is not None
