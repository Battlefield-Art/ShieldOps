"""Tests for shieldops.agents.security_posture."""

from __future__ import annotations

from shieldops.agents.security_posture.models import (
    PostureDomain,
    PostureStage,
    RiskCategory,
    SecurityPostureState,
)


class TestEnums:
    def test_posturestage_assess(self):
        assert PostureStage.ASSESS == "assess"

    def test_posturestage_score(self):
        assert PostureStage.SCORE == "score"

    def test_posturestage_prioritize(self):
        assert PostureStage.PRIORITIZE == "prioritize"

    def test_posturestage_recommend(self):
        assert PostureStage.RECOMMEND == "recommend"

    def test_posturedomain_identity(self):
        assert PostureDomain.IDENTITY == "identity"

    def test_posturedomain_network(self):
        assert PostureDomain.NETWORK == "network"

    def test_posturedomain_endpoint(self):
        assert PostureDomain.ENDPOINT == "endpoint"

    def test_posturedomain_cloud(self):
        assert PostureDomain.CLOUD == "cloud"

    def test_riskcategory_critical(self):
        assert RiskCategory.CRITICAL == "critical"

    def test_riskcategory_high(self):
        assert RiskCategory.HIGH == "high"

    def test_riskcategory_medium(self):
        assert RiskCategory.MEDIUM == "medium"

    def test_riskcategory_low(self):
        assert RiskCategory.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = SecurityPostureState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.security_posture.graph import (
            create_security_posture_graph,
        )

        sg = create_security_posture_graph()
        assert sg.compile() is not None
