"""Tests for the Risk Scoring agent."""

from __future__ import annotations

import time

import pytest

from shieldops.agents.risk_scoring.models import (
    ActionDecision,
    MitreTactic,
    RiskEntity,
    RiskLevel,
    RiskScoringState,
    RiskStage,
    SecurityObservation,
)
from shieldops.agents.risk_scoring.tools import RiskScoringToolkit


class TestRiskScoringModels:
    def test_risk_stage_values(self) -> None:
        assert RiskStage.COLLECT == "collect"
        assert RiskStage.ENRICH == "enrich"
        assert RiskStage.AGGREGATE == "aggregate"
        assert RiskStage.SCORE == "score"
        assert RiskStage.DECIDE == "decide"

    def test_mitre_tactic_values(self) -> None:
        assert MitreTactic.INITIAL_ACCESS == "initial_access"
        assert MitreTactic.LATERAL_MOVEMENT == "lateral_movement"
        assert MitreTactic.EXFILTRATION == "exfiltration"

    def test_risk_level_values(self) -> None:
        assert RiskLevel.LOW == "low"
        assert RiskLevel.CRITICAL == "critical"

    def test_action_decision_values(self) -> None:
        assert ActionDecision.AUTONOMOUS == "autonomous"
        assert ActionDecision.HUMAN_APPROVAL == "human_approval"

    def test_security_observation_defaults(self) -> None:
        obs = SecurityObservation()
        assert obs.source == ""
        assert obs.raw_score == 0.0
        assert obs.entity_type == "host"

    def test_risk_entity_defaults(self) -> None:
        entity = RiskEntity()
        assert entity.composite_score == 0.0
        assert entity.risk_level == RiskLevel.LOW

    def test_risk_scoring_state_defaults(self) -> None:
        state = RiskScoringState()
        assert state.stage == RiskStage.COLLECT
        assert state.autonomous_threshold == 0.85
        assert state.approval_threshold == 0.5


class TestRiskScoringToolkit:
    @pytest.mark.asyncio
    async def test_collect_no_client(self) -> None:
        toolkit = RiskScoringToolkit()
        result = await toolkit.collect_observations()
        assert result == []

    @pytest.mark.asyncio
    async def test_enrich_brute_force(self) -> None:
        toolkit = RiskScoringToolkit()
        obs = {"detection_name": "brute_force_login", "raw_score": 0.6}
        result = await toolkit.enrich_with_mitre(obs)
        assert result["mitre_tactic"] == "credential_access"
        assert result["mitre_technique"] == "T1110"

    @pytest.mark.asyncio
    async def test_enrich_phishing(self) -> None:
        toolkit = RiskScoringToolkit()
        obs = {"detection_name": "phishing_email_detected", "raw_score": 0.5}
        result = await toolkit.enrich_with_mitre(obs)
        assert result["mitre_tactic"] == "initial_access"

    @pytest.mark.asyncio
    async def test_enrich_unknown(self) -> None:
        toolkit = RiskScoringToolkit()
        obs = {"detection_name": "custom_detection", "raw_score": 0.3}
        result = await toolkit.enrich_with_mitre(obs)
        assert "mitre_tactic" not in result or result.get("mitre_tactic") == obs.get("mitre_tactic")

    @pytest.mark.asyncio
    async def test_entity_criticality_no_client(self) -> None:
        toolkit = RiskScoringToolkit()
        result = await toolkit.get_entity_criticality("host-1")
        assert result["criticality"] == 0.5

    @pytest.mark.asyncio
    async def test_threat_intel_no_client(self) -> None:
        toolkit = RiskScoringToolkit()
        result = await toolkit.check_threat_intel("1.2.3.4")
        assert result["known_malicious"] is False

    def test_composite_score_empty(self) -> None:
        toolkit = RiskScoringToolkit()
        result = toolkit.compute_composite_score([])
        assert result["composite_score"] == 0.0
        assert result["risk_level"] == "low"

    def test_composite_score_critical(self) -> None:
        toolkit = RiskScoringToolkit()
        now = time.time()
        observations = [
            {
                "mitre_tactic": "initial_access",
                "source": "ids",
                "raw_score": 0.9,
                "timestamp": now - 300,
            },
            {
                "mitre_tactic": "execution",
                "source": "edr",
                "raw_score": 0.95,
                "timestamp": now - 200,
            },
            {
                "mitre_tactic": "persistence",
                "source": "siem",
                "raw_score": 0.85,
                "timestamp": now - 100,
            },
            {
                "mitre_tactic": "lateral_movement",
                "source": "ndr",
                "raw_score": 0.9,
                "timestamp": now,
            },
            {
                "mitre_tactic": "exfiltration",
                "source": "dlp",
                "raw_score": 0.92,
                "timestamp": now + 60,
            },
        ]
        result = toolkit.compute_composite_score(observations, entity_criticality=0.9)
        assert result["composite_score"] >= 0.85
        assert result["risk_level"] == "critical"
        assert len(result["unique_tactics"]) == 5

    def test_composite_score_low(self) -> None:
        toolkit = RiskScoringToolkit()
        observations = [
            {
                "mitre_tactic": "discovery",
                "source": "siem",
                "raw_score": 0.1,
                "timestamp": 1.0,
            }
        ]
        result = toolkit.compute_composite_score(observations, entity_criticality=0.1)
        assert result["risk_level"] in ("low", "medium")

    def test_decide_action_autonomous(self) -> None:
        toolkit = RiskScoringToolkit()
        result = toolkit.decide_action(0.9)
        assert result["decision"] == "autonomous"
        assert "auto_contain" in result["recommended_actions"]

    def test_decide_action_human_approval(self) -> None:
        toolkit = RiskScoringToolkit()
        result = toolkit.decide_action(0.7)
        assert result["decision"] == "human_approval"

    def test_decide_action_monitor(self) -> None:
        toolkit = RiskScoringToolkit()
        result = toolkit.decide_action(0.4)
        assert result["decision"] == "monitor"

    def test_decide_action_no_action(self) -> None:
        toolkit = RiskScoringToolkit()
        result = toolkit.decide_action(0.1)
        assert result["decision"] == "no_action"
