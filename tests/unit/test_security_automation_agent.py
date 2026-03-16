"""Unit tests for the Security Automation Agent — models, toolkit, nodes, and edge cases."""

from __future__ import annotations

import pytest

from shieldops.agents.security_automation.models import (
    AutomationStage,
    ContainmentAction,
    ContainmentResult,
    PlaybookCandidate,
    PlaybookMatch,
    RiskAlert,
    SecurityAutomationState,
)
from shieldops.agents.security_automation.tools import SecurityAutomationToolkit

# =====================================================================
# Enum Tests
# =====================================================================


class TestAutomationStage:
    """Tests for AutomationStage enum."""

    def test_enum_values(self) -> None:
        assert AutomationStage.TRIAGE == "triage"
        assert AutomationStage.SELECT_PLAYBOOK == "select_playbook"
        assert AutomationStage.EXECUTE == "execute"
        assert AutomationStage.VALIDATE == "validate"
        assert AutomationStage.LEARN == "learn"

    def test_enum_membership(self) -> None:
        assert len(AutomationStage) == 5

    def test_string_comparison(self) -> None:
        assert AutomationStage("triage") is AutomationStage.TRIAGE


class TestContainmentAction:
    """Tests for ContainmentAction enum."""

    def test_enum_values(self) -> None:
        assert ContainmentAction.ISOLATE_HOST == "isolate_host"
        assert ContainmentAction.BLOCK_IP == "block_ip"
        assert ContainmentAction.DISABLE_ACCOUNT == "disable_account"
        assert ContainmentAction.QUARANTINE_FILE == "quarantine_file"
        assert ContainmentAction.REVOKE_TOKEN == "revoke_token"
        assert ContainmentAction.NONE == "none"

    def test_enum_membership(self) -> None:
        assert len(ContainmentAction) == 6


class TestPlaybookMatch:
    """Tests for PlaybookMatch enum."""

    def test_enum_values(self) -> None:
        assert PlaybookMatch.EXACT == "exact"
        assert PlaybookMatch.PARTIAL == "partial"
        assert PlaybookMatch.FALLBACK == "fallback"
        assert PlaybookMatch.NONE == "none"

    def test_enum_membership(self) -> None:
        assert len(PlaybookMatch) == 4


# =====================================================================
# Model Tests
# =====================================================================


class TestRiskAlert:
    """Tests for RiskAlert model."""

    def test_creation_with_required_fields(self) -> None:
        alert = RiskAlert(
            entity="host-prod-01",
            entity_type="host",
            composite_score=85.0,
            risk_level="high",
        )
        assert alert.entity == "host-prod-01"
        assert alert.entity_type == "host"
        assert alert.composite_score == 85.0
        assert alert.risk_level == "high"
        assert alert.tactics_seen == []
        assert alert.source_observations == []

    def test_creation_with_all_fields(self) -> None:
        alert = RiskAlert(
            entity="user-admin",
            entity_type="user",
            composite_score=92.5,
            risk_level="critical",
            tactics_seen=["credential_access", "lateral_movement"],
            source_observations=[
                {"source": "siem", "event": "brute_force"},
            ],
        )
        assert len(alert.tactics_seen) == 2
        assert len(alert.source_observations) == 1

    def test_score_validation_rejects_negative(self) -> None:
        with pytest.raises(ValueError):
            RiskAlert(
                entity="x",
                entity_type="host",
                composite_score=-1.0,
                risk_level="low",
            )


class TestPlaybookCandidate:
    """Tests for PlaybookCandidate model."""

    def test_defaults(self) -> None:
        pb = PlaybookCandidate(playbook_id="pb-1", name="Test")
        assert pb.match_type == PlaybookMatch.NONE
        assert pb.confidence == 0.0
        assert pb.estimated_duration_seconds == 0
        assert pb.actions == []

    def test_confidence_bounds(self) -> None:
        with pytest.raises(ValueError):
            PlaybookCandidate(playbook_id="pb-1", name="Test", confidence=1.5)


class TestContainmentResult:
    """Tests for ContainmentResult model."""

    def test_creation(self) -> None:
        result = ContainmentResult(
            action=ContainmentAction.BLOCK_IP,
            target="192.168.1.100",
            success=True,
            rollback_available=True,
        )
        assert result.action == ContainmentAction.BLOCK_IP
        assert result.success is True
        assert result.rollback_available is True
        assert result.duration_seconds == 0.0


class TestSecurityAutomationState:
    """Tests for SecurityAutomationState model."""

    def test_defaults(self) -> None:
        state = SecurityAutomationState()
        assert state.stage == AutomationStage.TRIAGE
        assert state.alerts == []
        assert state.triaged_alerts == []
        assert state.selected_playbook is None
        assert state.containment_results == []
        assert state.dry_run is True
        assert state.validation_passed is None
        assert state.learning_outcome is None
        assert state.confidence_score == 0.0
        assert state.autonomous_threshold == 0.85
        assert state.error is None

    def test_roundtrip_serialization(self) -> None:
        state = SecurityAutomationState(
            request_id="sa-test",
            alerts=[
                RiskAlert(
                    entity="h1",
                    entity_type="host",
                    composite_score=80.0,
                    risk_level="high",
                )
            ],
        )
        data = state.model_dump()
        restored = SecurityAutomationState.model_validate(data)
        assert restored.request_id == "sa-test"
        assert len(restored.alerts) == 1


# =====================================================================
# Toolkit Tests
# =====================================================================


def _make_alert(
    entity: str = "host-01",
    entity_type: str = "host",
    score: float = 75.0,
    risk_level: str = "high",
    tactics: list[str] | None = None,
) -> RiskAlert:
    return RiskAlert(
        entity=entity,
        entity_type=entity_type,
        composite_score=score,
        risk_level=risk_level,
        tactics_seen=tactics or [],
    )


class TestTriageAlerts:
    """Tests for SecurityAutomationToolkit.triage_alerts."""

    def test_filters_below_threshold(self) -> None:
        toolkit = SecurityAutomationToolkit(risk_threshold=50.0)
        alerts = [
            _make_alert(entity="a", score=80.0),
            _make_alert(entity="b", score=30.0),
            _make_alert(entity="c", score=60.0),
        ]
        result = toolkit.triage_alerts(alerts)
        assert len(result) == 2
        assert result[0].entity == "a"
        assert result[1].entity == "c"

    def test_empty_alerts(self) -> None:
        toolkit = SecurityAutomationToolkit()
        assert toolkit.triage_alerts([]) == []

    def test_custom_threshold(self) -> None:
        toolkit = SecurityAutomationToolkit(risk_threshold=50.0)
        alerts = [_make_alert(score=40.0)]
        # Override threshold at call time
        assert len(toolkit.triage_alerts(alerts, threshold=30.0)) == 1
        assert len(toolkit.triage_alerts(alerts, threshold=50.0)) == 0

    def test_sorts_by_score_descending(self) -> None:
        toolkit = SecurityAutomationToolkit(risk_threshold=0.0)
        alerts = [
            _make_alert(entity="low", score=10.0),
            _make_alert(entity="high", score=90.0),
            _make_alert(entity="mid", score=50.0),
        ]
        result = toolkit.triage_alerts(alerts)
        assert [a.entity for a in result] == ["high", "mid", "low"]


class TestMatchPlaybook:
    """Tests for SecurityAutomationToolkit.match_playbook."""

    def test_exact_match_host_lateral_movement(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(
            entity_type="host",
            tactics=["lateral_movement", "execution", "command_and_control"],
        )
        pb = toolkit.match_playbook(alert)
        assert pb.match_type == PlaybookMatch.EXACT
        assert pb.playbook_id == "pb-host-isolate-001"
        assert pb.confidence > 0.7

    def test_exact_match_user_credential_access(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(
            entity_type="user",
            tactics=["credential_access", "initial_access"],
        )
        pb = toolkit.match_playbook(alert)
        assert pb.match_type == PlaybookMatch.EXACT
        assert pb.playbook_id == "pb-account-disable-001"

    def test_partial_match(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(
            entity_type="ip",
            tactics=["command_and_control"],
        )
        pb = toolkit.match_playbook(alert)
        assert pb.match_type == PlaybookMatch.PARTIAL
        assert pb.playbook_id == "pb-ip-block-001"

    def test_no_match(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(
            entity_type="unknown",
            tactics=["nonexistent_tactic"],
        )
        pb = toolkit.match_playbook(alert)
        assert pb.match_type == PlaybookMatch.NONE
        assert pb.confidence == 0.0

    def test_fallback_match_entity_type_mismatch(self) -> None:
        toolkit = SecurityAutomationToolkit()
        # IP entity but host-only playbook tactics
        alert = _make_alert(
            entity_type="ip",
            tactics=["lateral_movement", "execution"],
        )
        pb = toolkit.match_playbook(alert)
        # Should fall back since IP entity doesn't match host playbook
        assert pb.match_type == PlaybookMatch.FALLBACK


class TestExecuteContainment:
    """Tests for SecurityAutomationToolkit.execute_containment."""

    @pytest.mark.asyncio
    async def test_dry_run_always_succeeds(self) -> None:
        toolkit = SecurityAutomationToolkit()
        result = await toolkit.execute_containment(
            action=ContainmentAction.BLOCK_IP,
            target="10.0.0.1",
            dry_run=True,
        )
        assert result.success is True
        assert "DRY RUN" in result.details
        assert result.rollback_available is True

    @pytest.mark.asyncio
    async def test_dry_run_none_action_no_rollback(self) -> None:
        toolkit = SecurityAutomationToolkit()
        result = await toolkit.execute_containment(
            action=ContainmentAction.NONE,
            target="x",
            dry_run=True,
        )
        assert result.success is True
        assert result.rollback_available is False

    @pytest.mark.asyncio
    async def test_live_execution(self) -> None:
        toolkit = SecurityAutomationToolkit()
        result = await toolkit.execute_containment(
            action=ContainmentAction.ISOLATE_HOST,
            target="host-prod-01",
            dry_run=False,
        )
        assert result.success is True
        assert result.action == ContainmentAction.ISOLATE_HOST


class TestValidateContainment:
    """Tests for SecurityAutomationToolkit.validate_containment."""

    def test_all_success(self) -> None:
        toolkit = SecurityAutomationToolkit()
        results = [
            ContainmentResult(
                action=ContainmentAction.BLOCK_IP,
                target="x",
                success=True,
            ),
            ContainmentResult(
                action=ContainmentAction.REVOKE_TOKEN,
                target="y",
                success=True,
            ),
        ]
        assert toolkit.validate_containment(results) is True

    def test_partial_failure(self) -> None:
        toolkit = SecurityAutomationToolkit()
        results = [
            ContainmentResult(
                action=ContainmentAction.BLOCK_IP,
                target="x",
                success=True,
            ),
            ContainmentResult(
                action=ContainmentAction.ISOLATE_HOST,
                target="y",
                success=False,
            ),
        ]
        assert toolkit.validate_containment(results) is False

    def test_empty_results(self) -> None:
        toolkit = SecurityAutomationToolkit()
        assert toolkit.validate_containment([]) is False


class TestRecordLearning:
    """Tests for SecurityAutomationToolkit.record_learning."""

    def test_records_accepted_outcome(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(entity="h1")
        playbook = PlaybookCandidate(
            playbook_id="pb-1",
            name="Test",
            confidence=0.9,
        )
        results = [
            ContainmentResult(
                action=ContainmentAction.BLOCK_IP,
                target="h1",
                success=True,
            ),
        ]
        outcome = toolkit.record_learning(
            alert=alert,
            playbook=playbook,
            results=results,
            accepted=True,
            feedback="Worked well",
        )
        assert outcome.accepted is True
        assert outcome.success is True
        assert outcome.feedback == "Worked well"
        assert len(toolkit.learning_history) == 1

    def test_records_rejected_outcome(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert(entity="h2")
        playbook = PlaybookCandidate(playbook_id="pb-2", name="Test", confidence=0.5)
        results = [
            ContainmentResult(
                action=ContainmentAction.ISOLATE_HOST,
                target="h2",
                success=False,
            ),
        ]
        outcome = toolkit.record_learning(
            alert=alert,
            playbook=playbook,
            results=results,
            accepted=False,
        )
        assert outcome.accepted is False
        assert outcome.success is False

    def test_learning_history_accumulates(self) -> None:
        toolkit = SecurityAutomationToolkit()
        alert = _make_alert()
        pb = PlaybookCandidate(playbook_id="pb-x", name="X", confidence=0.8)
        r = [
            ContainmentResult(
                action=ContainmentAction.BLOCK_IP,
                target="t",
                success=True,
            )
        ]
        toolkit.record_learning(alert, pb, r)
        toolkit.record_learning(alert, pb, r)
        toolkit.record_learning(alert, pb, r)
        assert len(toolkit.learning_history) == 3


# =====================================================================
# Node Tests (async)
# =====================================================================


class TestTriageAlertsNode:
    """Tests for the triage_alerts node function."""

    @pytest.mark.asyncio
    async def test_triage_filters_and_sorts(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            set_toolkit,
            triage_alerts,
        )

        toolkit = SecurityAutomationToolkit(risk_threshold=50.0)
        set_toolkit(toolkit)

        state = SecurityAutomationState(
            request_id="test-1",
            alerts=[
                _make_alert(entity="low", score=20.0),
                _make_alert(entity="high", score=90.0),
                _make_alert(entity="mid", score=60.0),
            ],
        )

        result = await triage_alerts(state)
        assert len(result["triaged_alerts"]) == 2
        assert result["triaged_alerts"][0].entity == "high"
        assert result["stage"] == AutomationStage.SELECT_PLAYBOOK

    @pytest.mark.asyncio
    async def test_triage_empty_alerts(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            set_toolkit,
            triage_alerts,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(request_id="test-2")
        result = await triage_alerts(state)
        assert result["triaged_alerts"] == []


class TestSelectPlaybookNode:
    """Tests for the select_playbook node function."""

    @pytest.mark.asyncio
    async def test_selects_playbook_for_triaged_alert(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            select_playbook,
            set_toolkit,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(
            request_id="test-3",
            triaged_alerts=[
                _make_alert(
                    entity_type="host",
                    tactics=["lateral_movement", "execution"],
                ),
            ],
        )

        result = await select_playbook(state)
        assert result["selected_playbook"] is not None
        assert result["selected_playbook"].playbook_id == "pb-host-isolate-001"

    @pytest.mark.asyncio
    async def test_skips_when_no_triaged_alerts(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            select_playbook,
            set_toolkit,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(request_id="test-4")
        result = await select_playbook(state)
        assert "selected_playbook" not in result
        assert result["stage"] == AutomationStage.LEARN


class TestExecuteResponseNode:
    """Tests for the execute_response node function."""

    @pytest.mark.asyncio
    async def test_executes_playbook_actions_dry_run(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            execute_response,
            set_toolkit,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(
            request_id="test-5",
            triaged_alerts=[_make_alert(entity="target-host")],
            selected_playbook=PlaybookCandidate(
                playbook_id="pb-1",
                name="Test",
                confidence=0.9,
                actions=["isolate_host", "revoke_token"],
            ),
            dry_run=True,
        )

        result = await execute_response(state)
        assert len(result["containment_results"]) == 2
        assert all(r.success for r in result["containment_results"])
        assert all("DRY RUN" in r.details for r in result["containment_results"])

    @pytest.mark.asyncio
    async def test_skips_when_no_playbook(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            execute_response,
            set_toolkit,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(request_id="test-6")
        result = await execute_response(state)
        assert result.get("containment_results", []) == []
        assert result["stage"] == AutomationStage.VALIDATE


class TestValidateAndLearnNode:
    """Tests for the validate_and_learn node function."""

    @pytest.mark.asyncio
    async def test_validates_successful_containment(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            set_toolkit,
            validate_and_learn,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(
            request_id="test-7",
            triaged_alerts=[_make_alert(entity="h1")],
            selected_playbook=PlaybookCandidate(playbook_id="pb-1", name="T", confidence=0.9),
            containment_results=[
                ContainmentResult(
                    action=ContainmentAction.BLOCK_IP,
                    target="h1",
                    success=True,
                ),
            ],
        )

        result = await validate_and_learn(state)
        assert result["validation_passed"] is True
        assert result["learning_outcome"] is not None
        assert result["learning_outcome"].accepted is True

    @pytest.mark.asyncio
    async def test_rejects_failed_containment(self) -> None:
        from shieldops.agents.security_automation.nodes import (
            set_toolkit,
            validate_and_learn,
        )

        set_toolkit(SecurityAutomationToolkit())
        state = SecurityAutomationState(
            request_id="test-8",
            triaged_alerts=[_make_alert(entity="h2")],
            selected_playbook=PlaybookCandidate(playbook_id="pb-2", name="T", confidence=0.5),
            containment_results=[
                ContainmentResult(
                    action=ContainmentAction.ISOLATE_HOST,
                    target="h2",
                    success=False,
                ),
            ],
        )

        result = await validate_and_learn(state)
        assert result["validation_passed"] is False
        assert result["learning_outcome"].accepted is False


# =====================================================================
# Prompt Tests
# =====================================================================


class TestPrompts:
    """Tests for prompt template existence and content."""

    def test_prompts_are_non_empty_strings(self) -> None:
        from shieldops.agents.security_automation.prompts import (
            SYSTEM_EXECUTE,
            SYSTEM_SELECT_PLAYBOOK,
            SYSTEM_TRIAGE,
            SYSTEM_VALIDATE,
        )

        assert isinstance(SYSTEM_TRIAGE, str) and len(SYSTEM_TRIAGE) > 50
        assert isinstance(SYSTEM_SELECT_PLAYBOOK, str) and len(SYSTEM_SELECT_PLAYBOOK) > 50
        assert isinstance(SYSTEM_EXECUTE, str) and len(SYSTEM_EXECUTE) > 50
        assert isinstance(SYSTEM_VALIDATE, str) and len(SYSTEM_VALIDATE) > 50

    def test_triage_prompt_mentions_rba(self) -> None:
        from shieldops.agents.security_automation.prompts import SYSTEM_TRIAGE

        assert "RBA" in SYSTEM_TRIAGE or "risk" in SYSTEM_TRIAGE.lower()

    def test_execute_prompt_mentions_dry_run(self) -> None:
        from shieldops.agents.security_automation.prompts import (
            SYSTEM_EXECUTE,
        )

        assert "dry-run" in SYSTEM_EXECUTE.lower() or "dry_run" in SYSTEM_EXECUTE.lower()


# =====================================================================
# Graph Structure Tests
# =====================================================================


class TestGraphStructure:
    """Tests for the LangGraph workflow definition."""

    def test_graph_creates_successfully(self) -> None:
        from shieldops.agents.security_automation.graph import (
            create_security_automation_graph,
        )

        graph = create_security_automation_graph()
        assert graph is not None

    def test_graph_compiles(self) -> None:
        from shieldops.agents.security_automation.graph import (
            create_security_automation_graph,
        )

        graph = create_security_automation_graph()
        app = graph.compile()
        assert app is not None
