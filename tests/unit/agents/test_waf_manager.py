"""Tests for shieldops.agents.waf_manager."""

from __future__ import annotations

import pytest

from shieldops.agents.waf_manager.models import (
    AttackCategory,
    AttackEvent,
    CoverageGap,
    RuleAction,
    WAFManagerState,
    WAFRule,
    WAFStage,
)


def _state(**kw) -> WAFManagerState:
    return WAFManagerState(**kw)


class TestEnums:
    def test_waf_stage_values(self):
        assert WAFStage.INGEST == "ingest"
        assert WAFStage.ANALYZE_ATTACKS == "analyze_attacks"
        assert WAFStage.EVALUATE_COVERAGE == "evaluate_coverage"
        assert WAFStage.TUNE_RULES == "tune_rules"
        assert WAFStage.REDUCE_FALSE_POSITIVES == "reduce_false_positives"
        assert WAFStage.AUTO_BLOCK == "auto_block"
        assert WAFStage.REPORT == "report"

    def test_attack_category_values(self):
        assert AttackCategory.SQL_INJECTION == "sql_injection"
        assert AttackCategory.XSS == "xss"
        assert AttackCategory.COMMAND_INJECTION == "command_injection"
        assert AttackCategory.PATH_TRAVERSAL == "path_traversal"
        assert AttackCategory.SSRF == "ssrf"
        assert AttackCategory.BROKEN_AUTH == "broken_auth"
        assert AttackCategory.SENSITIVE_DATA == "sensitive_data"
        assert AttackCategory.XXE == "xxe"
        assert AttackCategory.INSECURE_DESERIALIZATION == "insecure_deserialization"
        assert AttackCategory.SECURITY_MISCONFIGURATION == "security_misconfiguration"
        assert AttackCategory.CSRF == "csrf"
        assert AttackCategory.BOT_ATTACK == "bot_attack"
        assert AttackCategory.API_ABUSE == "api_abuse"
        assert AttackCategory.UNKNOWN == "unknown"

    def test_rule_action_values(self):
        assert RuleAction.BLOCK == "block"
        assert RuleAction.ALLOW == "allow"
        assert RuleAction.LOG == "log"
        assert RuleAction.CHALLENGE == "challenge"
        assert RuleAction.RATE_LIMIT == "rate_limit"
        assert RuleAction.REDIRECT == "redirect"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == WAFStage.INGEST
        assert s.waf_provider == ""
        assert s.time_window_hours == 24
        assert s.active_rules == []
        assert s.proposed_rules == []
        assert s.disabled_rules == []
        assert s.attack_events == []
        assert s.attack_summary == {}
        assert s.top_attack_sources == []
        assert s.coverage_gaps == []
        assert s.owasp_coverage_pct == 0.0
        assert s.false_positives == []
        assert s.fp_reduction_actions == []
        assert s.auto_blocked_ips == []
        assert s.block_recommendations == []
        assert s.reasoning_chain == []
        assert s.current_step == ""
        assert s.session_start == 0.0
        assert s.session_duration_ms == 0.0
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(
            tenant_id="t-01",
            waf_provider="cloudflare",
            owasp_coverage_pct=87.5,
        )
        assert s.tenant_id == "t-01"
        assert s.waf_provider == "cloudflare"
        assert s.owasp_coverage_pct == 87.5

    def test_waf_rule_defaults(self):
        r = WAFRule()
        assert r.rule_id == ""
        assert r.name == ""
        assert r.description == ""
        assert r.pattern == ""
        assert r.action == RuleAction.BLOCK
        assert r.category == AttackCategory.UNKNOWN
        assert r.severity == "medium"
        assert r.enabled is True
        assert r.false_positive_rate == 0.0
        assert r.hit_count == 0
        assert r.confidence == 0.0
        assert r.metadata == {}

    def test_attack_event_defaults(self):
        e = AttackEvent()
        assert e.event_id == ""
        assert e.timestamp == 0.0
        assert e.source_ip == ""
        assert e.target_url == ""
        assert e.method == "GET"
        assert e.category == AttackCategory.UNKNOWN
        assert e.matched_rule_id == ""
        assert e.action_taken == RuleAction.LOG
        assert e.payload_snippet == ""
        assert e.severity == "medium"
        assert e.risk_score == 0.0
        assert e.is_false_positive is False
        assert e.metadata == {}

    def test_coverage_gap_defaults(self):
        g = CoverageGap()
        assert g.owasp_id == ""
        assert g.owasp_name == ""
        assert g.category == AttackCategory.UNKNOWN
        assert g.covered is False
        assert g.rule_count == 0
        assert g.gap_description == ""
        assert g.recommended_rules == []
        assert g.severity == "high"


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.waf_manager.tools import WAFManagerToolkit

        return WAFManagerToolkit()

    @pytest.mark.asyncio
    async def test_load_active_rules(self, toolkit):
        result = await toolkit.load_active_rules()
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_analyze_attack_patterns(self, toolkit):
        events = await toolkit.ingest_waf_logs(time_window_hours=24, waf_provider="")
        result = await toolkit.analyze_attack_patterns(events)
        assert isinstance(result, dict)


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.waf_manager.graph import (
            create_waf_manager_graph,
        )

        sg = create_waf_manager_graph()
        assert sg.compile() is not None

    def test_graph_has_nodes(self):
        from shieldops.agents.waf_manager.graph import (
            create_waf_manager_graph,
        )

        sg = create_waf_manager_graph()
        compiled = sg.compile()
        assert compiled is not None
