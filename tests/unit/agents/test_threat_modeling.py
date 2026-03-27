"""Tests for shieldops.agents.threat_modeling."""

from __future__ import annotations

from shieldops.agents.threat_modeling.models import (
    ModelingStage,
    StrideCategory,
    ThreatLikelihood,
    ThreatModelingState,
)


class TestEnums:
    def test_modelingstage_discover(self):
        assert ModelingStage.DISCOVER == "discover"

    def test_modelingstage_analyze(self):
        assert ModelingStage.ANALYZE == "analyze"

    def test_modelingstage_assess(self):
        assert ModelingStage.ASSESS == "assess"

    def test_modelingstage_mitigate(self):
        assert ModelingStage.MITIGATE == "mitigate"

    def test_stridecategory_spoofing(self):
        assert StrideCategory.SPOOFING == "spoofing"

    def test_stridecategory_tampering(self):
        assert StrideCategory.TAMPERING == "tampering"

    def test_stridecategory_repudiation(self):
        assert StrideCategory.REPUDIATION == "repudiation"

    def test_stridecategory_information_disclosure(self):
        assert StrideCategory.INFORMATION_DISCLOSURE == "information_disclosure"

    def test_threatlikelihood_very_likely(self):
        assert ThreatLikelihood.VERY_LIKELY == "very_likely"

    def test_threatlikelihood_likely(self):
        assert ThreatLikelihood.LIKELY == "likely"

    def test_threatlikelihood_possible(self):
        assert ThreatLikelihood.POSSIBLE == "possible"

    def test_threatlikelihood_unlikely(self):
        assert ThreatLikelihood.UNLIKELY == "unlikely"


class TestModels:
    def test_state_defaults(self):
        s = ThreatModelingState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_modeling.graph import (
            create_threat_modeling_graph,
        )

        sg = create_threat_modeling_graph()
        assert sg.compile() is not None
