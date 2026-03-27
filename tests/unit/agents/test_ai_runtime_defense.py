"""Tests for shieldops.agents.ai_runtime_defense."""

from __future__ import annotations

from shieldops.agents.ai_runtime_defense.models import (
    AIRuntimeDefenseState,
    DefenseStage,
    FindingSeverity,
    ModelProvider,
)


class TestEnums:
    def test_defensestage_scan_prompts(self):
        assert DefenseStage.SCAN_PROMPTS == "scan_prompts"

    def test_defensestage_detect_exfiltration(self):
        assert DefenseStage.DETECT_EXFILTRATION == "detect_exfiltration"

    def test_defensestage_detect_abuse(self):
        assert DefenseStage.DETECT_ABUSE == "detect_abuse"

    def test_defensestage_scan_supply_chain(self):
        assert DefenseStage.SCAN_SUPPLY_CHAIN == "scan_supply_chain"

    def test_modelprovider_anthropic(self):
        assert ModelProvider.ANTHROPIC == "anthropic"

    def test_modelprovider_openai(self):
        assert ModelProvider.OPENAI == "openai"

    def test_modelprovider_azure(self):
        assert ModelProvider.AZURE == "azure"

    def test_modelprovider_bedrock(self):
        assert ModelProvider.BEDROCK == "bedrock"

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
        s = AIRuntimeDefenseState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_runtime_defense.graph import (
            create_ai_runtime_defense_graph,
        )

        sg = create_ai_runtime_defense_graph()
        assert sg.compile() is not None
