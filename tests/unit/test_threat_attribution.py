"""Unit tests for threat_attribution agent."""

from __future__ import annotations

import time

import pytest

from shieldops.agents.threat_attribution.models import (
    ActorProfile,
    AttributionAssessment,
    AttributionStage,
    ConfidenceLevel,
    ThreatActorType,
    ThreatAttributionState,
    TTPMapping,
)
from shieldops.agents.threat_attribution.tools import (
    ThreatAttributionToolkit,
)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class TestEnums:
    def test_attribution_stage_values(self):
        assert AttributionStage.COLLECT_EVIDENCE == "collect_evidence"
        assert AttributionStage.MAP_TTPS == "map_ttps"
        assert AttributionStage.REPORT == "report"

    def test_threat_actor_type_values(self):
        assert ThreatActorType.APT == "apt"
        assert ThreatActorType.NATION_STATE == "nation_state"
        assert ThreatActorType.UNKNOWN == "unknown"

    def test_confidence_level_values(self):
        assert ConfidenceLevel.HIGH == "high"
        assert ConfidenceLevel.UNATTRIBUTED == "unattributed"


class TestState:
    def test_defaults(self):
        state = ThreatAttributionState()
        assert state.request_id == ""
        assert state.tenant_id == ""
        assert state.error == ""
        assert state.stage == AttributionStage.COLLECT_EVIDENCE
        assert state.incident_id == ""
        assert state.ttp_mappings == []
        assert state.actor_profile.name == ""
        assert state.confidence == ConfidenceLevel.UNATTRIBUTED
        assert state.reasoning_chain == []
        assert state.session_start == 0.0

    def test_with_values(self):
        state = ThreatAttributionState(
            request_id="req-1",
            tenant_id="t-1",
            incident_id="inc-42",
            confidence=ConfidenceLevel.HIGH,
        )
        assert state.request_id == "req-1"
        assert state.confidence == ConfidenceLevel.HIGH


class TestModels:
    def test_ttp_mapping_defaults(self):
        m = TTPMapping()
        assert m.technique_id == ""
        assert m.technique_name == ""
        assert m.tactic == ""
        assert m.confidence == 0.0
        assert m.data_sources == []

    def test_actor_profile_defaults(self):
        p = ActorProfile()
        assert p.name == ""
        assert p.actor_type == ThreatActorType.UNKNOWN
        assert p.aliases == []
        assert p.motivation == ""

    def test_attribution_assessment_defaults(self):
        a = AttributionAssessment()
        assert a.attributed_actor == ""
        assert a.confidence == ConfidenceLevel.UNATTRIBUTED
        assert a.supporting_evidence == []
        assert a.mitre_techniques_matched == 0


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        return ThreatAttributionToolkit()

    @pytest.mark.asyncio
    async def test_collect_evidence_fallback(self, toolkit):
        evidence = await toolkit.collect_evidence("inc-1")
        assert len(evidence) == 5  # fallback baseline
        types = [e["type"] for e in evidence]
        assert "ip" in types
        assert "domain" in types
        assert "hash" in types

    @pytest.mark.asyncio
    async def test_map_ttps_from_evidence(self, toolkit):
        evidence = [
            {
                "description": "Powershell dropper executed",
                "value": "powershell.exe -enc ...",
            },
            {
                "description": "Lateral movement via SMB",
                "value": "smb connection to 10.0.0.5",
            },
            {
                "description": "Credential dump from LSASS",
                "value": "credential dump detected",
            },
        ]
        mappings = await toolkit.map_ttps(evidence)
        assert len(mappings) >= 2
        technique_ids = [m.technique_id for m in mappings]
        assert "T1059.001" in technique_ids  # powershell
        assert "T1021.002" in technique_ids  # smb

    @pytest.mark.asyncio
    async def test_map_ttps_no_match(self, toolkit):
        evidence = [{"description": "nothing relevant", "value": ""}]
        mappings = await toolkit.map_ttps(evidence)
        assert isinstance(mappings, list)

    @pytest.mark.asyncio
    async def test_profile_actor_match(self, toolkit):
        mappings = [
            TTPMapping(technique_id="T1566.001", tactic="Initial Access"),
            TTPMapping(technique_id="T1059.001", tactic="Execution"),
            TTPMapping(technique_id="T1071", tactic="C2"),
            TTPMapping(technique_id="T1027", tactic="Defense Evasion"),
        ]
        profile = await toolkit.profile_actor(mappings)
        assert profile.name == "APT29"
        assert profile.actor_type == ThreatActorType.APT

    @pytest.mark.asyncio
    async def test_profile_actor_no_match(self, toolkit):
        mappings = [
            TTPMapping(technique_id="T9999", tactic="Unknown"),
        ]
        profile = await toolkit.profile_actor(mappings)
        assert profile.name == "Unknown Actor"
        assert profile.actor_type == ThreatActorType.UNKNOWN

    @pytest.mark.asyncio
    async def test_assess_confidence_high(self, toolkit):
        mappings = [
            TTPMapping(
                technique_id=f"T{i}",
                tactic="test",
                confidence=0.8,
            )
            for i in range(5)
        ]
        profile = ActorProfile(name="APT29", actor_type=ThreatActorType.APT)
        assessment = await toolkit.assess_confidence(mappings, profile)
        assert assessment.confidence == ConfidenceLevel.HIGH
        assert assessment.attributed_actor == "APT29"
        assert assessment.mitre_techniques_matched == 5

    @pytest.mark.asyncio
    async def test_assess_confidence_low(self, toolkit):
        mappings = [
            TTPMapping(
                technique_id="T1",
                tactic="test",
                confidence=0.3,
            ),
        ]
        profile = ActorProfile(name="Unknown")
        assessment = await toolkit.assess_confidence(mappings, profile)
        assert assessment.confidence == ConfidenceLevel.LOW

    @pytest.mark.asyncio
    async def test_assess_confidence_unattributed(self, toolkit):
        mappings: list[TTPMapping] = []
        profile = ActorProfile(name="Unknown")
        assessment = await toolkit.assess_confidence(mappings, profile)
        assert assessment.confidence == ConfidenceLevel.UNATTRIBUTED

    def test_match_ttps_helper(self, toolkit):
        mappings = toolkit._match_ttps("phishing email with powershell payload and dns tunnel")
        technique_ids = [m.technique_id for m in mappings]
        assert "T1566" in technique_ids
        assert "T1059.001" in technique_ids
        assert "T1071.004" in technique_ids

    def test_match_actor_helper(self, toolkit):
        actor, sig, score = toolkit._match_actor(["T1566.001", "T1059.001", "T1071", "T1027"])
        assert actor == "APT29"
        assert score == 1.0

    def test_match_actor_no_overlap(self, toolkit):
        actor, sig, score = toolkit._match_actor(["T9999"])
        assert score == 0.0


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


class TestNodes:
    @pytest.mark.asyncio
    async def test_collect_evidence_node(self):
        from shieldops.agents.threat_attribution.nodes import (
            collect_evidence,
            set_toolkit,
        )

        set_toolkit(ThreatAttributionToolkit())
        state = ThreatAttributionState(incident_id="inc-1")
        result = await collect_evidence(state)
        assert result["stage"] == AttributionStage.MAP_TTPS
        assert len(result["reasoning_chain"]) > 0

    @pytest.mark.asyncio
    async def test_map_ttps_node(self):
        import json

        from shieldops.agents.threat_attribution.nodes import (
            map_ttps,
            set_toolkit,
        )

        set_toolkit(ThreatAttributionToolkit())
        evidence_data = json.dumps(
            {
                "_evidence": [
                    {
                        "description": "Powershell dropper",
                        "value": "powershell exec",
                    },
                ]
            }
        )
        state = ThreatAttributionState(
            incident_id="inc-1",
            reasoning_chain=[evidence_data],
        )
        result = await map_ttps(state)
        assert "ttp_mappings" in result
        assert result["stage"] == AttributionStage.PROFILE_ACTOR

    @pytest.mark.asyncio
    async def test_profile_actor_node(self):
        from shieldops.agents.threat_attribution.nodes import (
            profile_actor,
            set_toolkit,
        )

        set_toolkit(ThreatAttributionToolkit())
        state = ThreatAttributionState(
            incident_id="inc-1",
            ttp_mappings=[
                TTPMapping(
                    technique_id="T1566.001",
                    tactic="Initial Access",
                ),
            ],
        )
        result = await profile_actor(state)
        assert "actor_profile" in result
        assert result["stage"] == AttributionStage.ASSESS_CONFIDENCE

    @pytest.mark.asyncio
    async def test_assess_confidence_node(self):
        from shieldops.agents.threat_attribution.nodes import (
            assess_confidence,
            set_toolkit,
        )

        set_toolkit(ThreatAttributionToolkit())
        state = ThreatAttributionState(
            incident_id="inc-1",
            ttp_mappings=[
                TTPMapping(
                    technique_id="T1566",
                    tactic="Initial Access",
                    confidence=0.8,
                ),
            ],
            actor_profile=ActorProfile(
                name="APT29",
                actor_type=ThreatActorType.APT,
            ),
        )
        result = await assess_confidence(state)
        assert "confidence" in result
        assert "attribution_assessment" in result
        assert result["stage"] == AttributionStage.GENERATE_REPORT

    @pytest.mark.asyncio
    async def test_generate_report_node(self):
        from shieldops.agents.threat_attribution.nodes import (
            generate_report,
            set_toolkit,
        )

        set_toolkit(ThreatAttributionToolkit())
        state = ThreatAttributionState(
            incident_id="inc-1",
            session_start=time.time(),
            confidence=ConfidenceLevel.HIGH,
            actor_profile=ActorProfile(
                name="APT29",
                actor_type=ThreatActorType.APT,
            ),
            ttp_mappings=[
                TTPMapping(technique_id="T1566", tactic="IA"),
            ],
            attribution_assessment=AttributionAssessment(
                attributed_actor="APT29",
                confidence=ConfidenceLevel.HIGH,
            ),
        )
        result = await generate_report(state)
        assert result["stage"] == AttributionStage.REPORT


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.threat_attribution.graph import (
            create_threat_attribution_graph,
        )

        sg = create_threat_attribution_graph()
        app = sg.compile()
        assert app is not None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunner:
    def test_runner_init(self):
        from shieldops.agents.threat_attribution.runner import (
            ThreatAttributionRunner,
        )

        runner = ThreatAttributionRunner()
        assert runner is not None
