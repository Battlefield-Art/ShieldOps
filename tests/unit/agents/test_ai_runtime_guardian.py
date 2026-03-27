"""Tests for shieldops.agents.ai_runtime_guardian — AI runtime security guardrails."""

from __future__ import annotations

import pytest

from shieldops.agents.ai_runtime_guardian.models import (
    AIRuntimeGuardianState,
    AIThreatVector,
    GuardianStage,
    GuardrailAction,
    GuardrailEnforcement,
    ModelBehaviorAnalysis,
    PromptAttackDetection,
    ReasoningStep,
    RuntimeMonitor,
    ToolExecutionGuard,
)


def _state(**kw) -> AIRuntimeGuardianState:
    return AIRuntimeGuardianState(**kw)


class TestEnums:
    def test_guardian_stage_values(self):
        assert GuardianStage.MONITOR_AI_RUNTIME == "monitor_ai_runtime"
        assert GuardianStage.DETECT_PROMPT_ATTACKS == "detect_prompt_attacks"
        assert GuardianStage.ANALYZE_MODEL_BEHAVIOR == "analyze_model_behavior"
        assert GuardianStage.GUARD_TOOL_EXECUTION == "guard_tool_execution"
        assert GuardianStage.ENFORCE_GUARDRAILS == "enforce_guardrails"
        assert GuardianStage.REPORT == "report"

    def test_ai_threat_vector_values(self):
        assert AIThreatVector.PROMPT_INJECTION == "prompt_injection"
        assert AIThreatVector.MODEL_MANIPULATION == "model_manipulation"
        assert AIThreatVector.TOOL_ABUSE == "tool_abuse"
        assert AIThreatVector.DATA_POISONING == "data_poisoning"
        assert AIThreatVector.AGENT_HIJACKING == "agent_hijacking"
        assert AIThreatVector.OUTPUT_MANIPULATION == "output_manipulation"

    def test_guardrail_action_values(self):
        assert GuardrailAction.ALLOW == "allow"
        assert GuardrailAction.SANITIZE == "sanitize"
        assert GuardrailAction.BLOCK == "block"
        assert GuardrailAction.QUARANTINE == "quarantine"
        assert GuardrailAction.ALERT == "alert"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == GuardianStage.MONITOR_AI_RUNTIME
        assert s.monitors == []
        assert s.attacks == []
        assert s.behaviors == []
        assert s.tool_guards == []
        assert s.enforcements == []
        assert s.report == ""
        assert s.total_agents_monitored == 0
        assert s.attacks_blocked == 0
        assert s.guardrails_triggered == 0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(tenant_id="t-01", total_agents_monitored=10, attacks_blocked=3)
        assert s.tenant_id == "t-01"
        assert s.total_agents_monitored == 10
        assert s.attacks_blocked == 3

    def test_runtime_monitor_defaults(self):
        rm = RuntimeMonitor()
        assert rm.id == ""
        assert rm.agent_id == ""
        assert rm.model_name == ""
        assert rm.invocation_count == 0
        assert rm.avg_latency_ms == 0.0
        assert rm.error_rate_pct == 0.0
        assert rm.token_usage == 0
        assert rm.anomaly_score == 0.0
        assert rm.status == "healthy"

    def test_prompt_attack_detection_defaults(self):
        pad = PromptAttackDetection()
        assert pad.id == ""
        assert pad.agent_id == ""
        assert pad.threat_vector == AIThreatVector.PROMPT_INJECTION
        assert pad.confidence == 0.0
        assert pad.blocked is False
        assert pad.severity == "medium"

    def test_model_behavior_analysis_defaults(self):
        mba = ModelBehaviorAnalysis()
        assert mba.id == ""
        assert mba.drift_score == 0.0
        assert mba.output_consistency == 1.0
        assert mba.hallucination_rate == 0.0
        assert mba.safety_violations == 0
        assert mba.behavioral_flags == []

    def test_tool_execution_guard_defaults(self):
        teg = ToolExecutionGuard()
        assert teg.id == ""
        assert teg.tool_name == ""
        assert teg.action_taken == GuardrailAction.ALLOW
        assert teg.risk_score == 0.0
        assert teg.parameters_sanitized is False

    def test_guardrail_enforcement_defaults(self):
        ge = GuardrailEnforcement()
        assert ge.id == ""
        assert ge.rule_name == ""
        assert ge.action == GuardrailAction.ALLOW
        assert ge.threat_vector == AIThreatVector.PROMPT_INJECTION
        assert ge.policy_id == ""

    def test_reasoning_step_defaults(self):
        r = ReasoningStep()
        assert r.step == ""
        assert r.detail == ""
        assert r.confidence == 0.0
        assert r.metadata == {}


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.ai_runtime_guardian.tools import AIRuntimeGuardianToolkit

        return AIRuntimeGuardianToolkit()

    @pytest.mark.asyncio
    async def test_monitor_runtime(self, toolkit):
        result = await toolkit.monitor_runtime(tenant_id="t-01")
        assert isinstance(result, list)
        assert len(result) > 0
        assert all(isinstance(m, RuntimeMonitor) for m in result)

    @pytest.mark.asyncio
    async def test_detect_prompt_attacks(self, toolkit):
        monitors = await toolkit.monitor_runtime(tenant_id="t-01")
        result = await toolkit.detect_prompt_attacks(monitors)
        assert isinstance(result, list)
        assert all(isinstance(a, PromptAttackDetection) for a in result)

    @pytest.mark.asyncio
    async def test_analyze_model_behavior(self, toolkit):
        monitors = await toolkit.monitor_runtime(tenant_id="t-01")
        result = await toolkit.analyze_model_behavior(monitors)
        assert isinstance(result, list)
        assert all(isinstance(b, ModelBehaviorAnalysis) for b in result)

    @pytest.mark.asyncio
    async def test_guard_tool_execution(self, toolkit):
        monitors = await toolkit.monitor_runtime(tenant_id="t-01")
        attacks = await toolkit.detect_prompt_attacks(monitors)
        result = await toolkit.guard_tool_execution(monitors, attacks)
        assert isinstance(result, list)
        assert all(isinstance(g, ToolExecutionGuard) for g in result)

    @pytest.mark.asyncio
    async def test_enforce_guardrails(self, toolkit):
        monitors = await toolkit.monitor_runtime(tenant_id="t-01")
        attacks = await toolkit.detect_prompt_attacks(monitors)
        guards = await toolkit.guard_tool_execution(monitors, attacks)
        result = await toolkit.enforce_guardrails(attacks, guards)
        assert isinstance(result, list)
        assert all(isinstance(e, GuardrailEnforcement) for e in result)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.ai_runtime_guardian.graph import create_ai_runtime_guardian_graph

        sg = create_ai_runtime_guardian_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.ai_runtime_guardian.graph import create_ai_runtime_guardian_graph

        sg = create_ai_runtime_guardian_graph()
        compiled = sg.compile()
        assert compiled is not None
