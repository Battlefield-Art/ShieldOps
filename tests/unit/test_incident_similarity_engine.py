"""Tests for incident_similarity_engine."""

from __future__ import annotations

from shieldops.agents.incident_similarity_engine.models import (
    FeatureType,
    IncidentSimilarityEngineState,
    MatchQuality,
    SimilarityStage,
)


class TestEnums:
    def test_featuretype(self) -> None:
        assert FeatureType.TTP == "ttp"
        assert len(FeatureType) >= 3

    def test_matchquality(self) -> None:
        assert MatchQuality.EXACT == "exact"
        assert len(MatchQuality) >= 3

    def test_similaritystage(self) -> None:
        assert SimilarityStage.INGEST_INCIDENT == "ingest_incident"
        assert len(SimilarityStage) >= 3


class TestState:
    def test_defaults(self) -> None:
        s = IncidentSimilarityEngineState()
        assert s.error == ""

    def test_with_values(self) -> None:
        s = IncidentSimilarityEngineState(request_id="x", tenant_id="t")
        assert s.request_id == "x"
