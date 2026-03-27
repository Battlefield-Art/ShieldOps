"""Tests for shieldops.agents.supply_chain_security."""

from __future__ import annotations

from shieldops.agents.supply_chain_security.models import (
    DependencyRisk,
    PipelineThreat,
    SupplyChainSecurityState,
    SupplyChainStage,
)


class TestEnums:
    def test_supplychainstage_generate_sbom(self):
        assert SupplyChainStage.GENERATE_SBOM == "generate_sbom"

    def test_supplychainstage_scan_dependencies(self):
        assert SupplyChainStage.SCAN_DEPENDENCIES == "scan_dependencies"

    def test_supplychainstage_audit_cicd(self):
        assert SupplyChainStage.AUDIT_CICD == "audit_cicd"

    def test_supplychainstage_verify_signatures(self):
        assert SupplyChainStage.VERIFY_SIGNATURES == "verify_signatures"

    def test_dependencyrisk_critical(self):
        assert DependencyRisk.CRITICAL == "critical"

    def test_dependencyrisk_high(self):
        assert DependencyRisk.HIGH == "high"

    def test_dependencyrisk_medium(self):
        assert DependencyRisk.MEDIUM == "medium"

    def test_dependencyrisk_low(self):
        assert DependencyRisk.LOW == "low"

    def test_pipelinethreat_code_injection(self):
        assert PipelineThreat.CODE_INJECTION == "code_injection"

    def test_pipelinethreat_dependency_confusion(self):
        assert PipelineThreat.DEPENDENCY_CONFUSION == "dependency_confusion"

    def test_pipelinethreat_typosquatting(self):
        assert PipelineThreat.TYPOSQUATTING == "typosquatting"

    def test_pipelinethreat_compromised_action(self):
        assert PipelineThreat.COMPROMISED_ACTION == "compromised_action"


class TestModels:
    def test_state_defaults(self):
        s = SupplyChainSecurityState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.supply_chain_security.graph import (
            create_supply_chain_security_graph,
        )

        sg = create_supply_chain_security_graph()
        assert sg.compile() is not None
