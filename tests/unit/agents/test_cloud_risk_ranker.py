"""Tests for shieldops.agents.cloud_risk_ranker."""

from __future__ import annotations

from shieldops.agents.cloud_risk_ranker.models import (
    CloudRiskRankerState,
    ExploitabilityLevel,
    RankerStage,
    RiskCategory,
)


class TestEnums:
    def test_rankerstage_collect_cloud_findings(self):
        assert RankerStage.COLLECT_CLOUD_FINDINGS == "collect_cloud_findings"

    def test_rankerstage_correlate_attacker_tactics(self):
        assert RankerStage.CORRELATE_ATTACKER_TACTICS == "correlate_attacker_tactics"

    def test_rankerstage_rank_by_exploitability(self):
        assert RankerStage.RANK_BY_EXPLOITABILITY == "rank_by_exploitability"

    def test_rankerstage_generate_attack_paths(self):
        assert RankerStage.GENERATE_ATTACK_PATHS == "generate_attack_paths"

    def test_riskcategory_misconfiguration(self):
        assert RiskCategory.MISCONFIGURATION == "misconfiguration"

    def test_riskcategory_vulnerability(self):
        assert RiskCategory.VULNERABILITY == "vulnerability"

    def test_riskcategory_identity_exposure(self):
        assert RiskCategory.IDENTITY_EXPOSURE == "identity_exposure"

    def test_riskcategory_data_exposure(self):
        assert RiskCategory.DATA_EXPOSURE == "data_exposure"

    def test_exploitabilitylevel_actively_exploited(self):
        assert ExploitabilityLevel.ACTIVELY_EXPLOITED == "actively_exploited"

    def test_exploitabilitylevel_exploit_available(self):
        assert ExploitabilityLevel.EXPLOIT_AVAILABLE == "exploit_available"

    def test_exploitabilitylevel_proof_of_concept(self):
        assert ExploitabilityLevel.PROOF_OF_CONCEPT == "proof_of_concept"

    def test_exploitabilitylevel_theoretical(self):
        assert ExploitabilityLevel.THEORETICAL == "theoretical"


class TestModels:
    def test_state_defaults(self):
        s = CloudRiskRankerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.cloud_risk_ranker.graph import (
            create_cloud_risk_ranker_graph,
        )

        sg = create_cloud_risk_ranker_graph()
        assert sg.compile() is not None
