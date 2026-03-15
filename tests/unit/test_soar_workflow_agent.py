"""Unit tests for the SOAR Workflow Orchestrator Agent — models, toolkit, nodes, and graph."""

from __future__ import annotations

import pytest

from shieldops.agents.soar_workflow.models import (
    AlertIntake,
    EnrichmentResult,
    PlaybookType,
    ReasoningStep,
    ResponseAction,
    ResponseStage,
    ResponseStatus,
    SOARWorkflowState,
)
from shieldops.agents.soar_workflow.tools import SOARWorkflowToolkit, _classify_indicator
from shieldops.agents.soar_workflow.nodes import (
    enrich_context,
    execute_containment,
    execute_eradication,
    intake_and_classify,
    recover_and_report,
)
from shieldops.agents.soar_workflow.graph import build_graph, create_soar_workflow_graph
from shieldops.agents.soar_workflow.runner import SOARWorkflowRunner
from shieldops.agents.soar_workflow.prompts import (
    SYSTEM_CONTAIN,
    SYSTEM_ENRICH,
    SYSTEM_ERADICATE,
    SYSTEM_INTAKE,
    SYSTEM_RECOVER,
)


# =====================================================================
# Enum Tests
# =====================================================================


class TestResponseStage:
    """Tests for ResponseStage enum."""

    def test_enum_values(self) -> None:
        assert ResponseStage.INTAKE == "intake"
        assert ResponseStage.ENRICH == "enrich"
        assert ResponseStage.CONTAIN == "contain"
        assert ResponseStage.ERADICATE == "eradicate"
        assert ResponseStage.RECOVER == "recover"
        assert ResponseStage.LESSONS_LEARNED == "lessons_learned"

    def test_enum_membership(self) -> None:
        assert len(ResponseStage) == 6

    def test_string_comparison(self) -> None:
        assert ResponseStage("intake") is ResponseStage.INTAKE


class TestPlaybookType:
    """Tests for PlaybookType enum."""

    def test_enum_values(self) -> None:
        assert PlaybookType.CONTAINMENT == "containment"
        assert PlaybookType.ERADICATION == "eradication"
        assert PlaybookType.RECOVERY == "recovery"
        assert PlaybookType.NOTIFICATION == "notification"
        assert PlaybookType.FORENSIC == "forensic"

    def test_enum_membership(self) -> None:
        assert len(PlaybookType) == 5


class TestResponseStatus:
    """Tests for ResponseStatus enum."""

    def test_enum_values(self) -> None:
        assert ResponseStatus.PENDING == "pending"
        assert ResponseStatus.IN_PROGRESS == "in_progress"
        assert ResponseStatus.COMPLETED == "completed"
        assert ResponseStatus.FAILED == "failed"
        assert ResponseStatus.ESCALATED == "escalated"

    def test_enum_membership(self) -> None:
        assert len(ResponseStatus) == 5


# =====================================================================
# Model Tests
# =====================================================================


class TestAlertIntake:
    """Tests for AlertIntake model."""

    def test_defaults(self) -> None:
        alert = AlertIntake()
        assert alert.alert_id == ""
        assert alert.source == ""
        assert alert.severity == "medium"
        assert alert.description == ""
        assert alert.indicators == []
        assert alert.mitre_tactics == []

    def test_creation_with_values(self) -> None:
        alert = AlertIntake(
            alert_id="ALERT-001",
            source="splunk",
            severity="critical",
            description="Brute force detected",
            indicators=["10.0.0.1", "evil.com"],
            mitre_tactics=["TA0006-Credential Access"],
        )
        assert alert.alert_id == "ALERT-001"
        assert alert.source == "splunk"
        assert alert.severity == "critical"
        assert len(alert.indicators) == 2
        assert len(alert.mitre_tactics) == 1


class TestEnrichmentResult:
    """Tests for EnrichmentResult model."""

    def test_defaults(self) -> None:
        er = EnrichmentResult()
        assert er.indicator == ""
        assert er.enrichment_type == ""
        assert er.result == {}
        assert er.confidence == 0.0

    def test_confidence_bounds(self) -> None:
        er = EnrichmentResult(confidence=0.95)
        assert er.confidence == 0.95

    def test_confidence_validation(self) -> None:
        with pytest.raises(Exception):
            EnrichmentResult(confidence=1.5)


class TestResponseAction:
    """Tests for ResponseAction model."""

    def test_defaults(self) -> None:
        action = ResponseAction()
        assert action.action_id == ""
        assert action.playbook_type == PlaybookType.CONTAINMENT
        assert action.target == ""
        assert action.status == ResponseStatus.PENDING
        assert action.result == {}
        assert action.duration_ms == 0

    def test_creation_with_values(self) -> None:
        action = ResponseAction(
            action_id="ACT-001",
            playbook_type=PlaybookType.ERADICATION,
            target="host-01",
            status=ResponseStatus.COMPLETED,
            result={"success": True},
            duration_ms=1500,
        )
        assert action.action_id == "ACT-001"
        assert action.playbook_type == PlaybookType.ERADICATION
        assert action.status == ResponseStatus.COMPLETED
        assert action.duration_ms == 1500


class TestSOARWorkflowState:
    """Tests for SOARWorkflowState model."""

    def test_defaults(self) -> None:
        state = SOARWorkflowState()
        assert state.request_id == ""
        assert state.stage == ResponseStage.INTAKE
        assert state.alert == {}
        assert state.enrichments == []
        assert state.actions == []
        assert state.containment_status == ""
        assert state.eradication_status == ""
        assert state.recovery_status == ""
        assert state.lessons == []
        assert state.total_response_time_ms == 0
        assert state.reasoning_chain == []
        assert state.error == ""

    def test_model_dump_roundtrip(self) -> None:
        state = SOARWorkflowState(request_id="REQ-001")
        dumped = state.model_dump()
        restored = SOARWorkflowState(**dumped)
        assert restored.request_id == "REQ-001"


class TestReasoningStep:
    """Tests for ReasoningStep model."""

    def test_defaults(self) -> None:
        step = ReasoningStep()
        assert step.step == ""
        assert step.detail == ""
        assert step.confidence == 0.0
        assert step.metadata == {}


# =====================================================================
# Tools Tests
# =====================================================================


class TestClassifyIndicator:
    """Tests for _classify_indicator helper."""

    def test_ip_classification(self) -> None:
        assert _classify_indicator("10.0.0.1") == "ip"

    def test_email_classification(self) -> None:
        assert _classify_indicator("user@evil.com") == "email"

    def test_hash_md5(self) -> None:
        assert _classify_indicator("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_hash_sha256(self) -> None:
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _classify_indicator(h) == "hash"

    def test_domain_classification(self) -> None:
        assert _classify_indicator("evil.example.com") == "domain"


class TestSOARWorkflowToolkit:
    """Tests for SOARWorkflowToolkit."""

    def test_init_no_clients(self) -> None:
        toolkit = SOARWorkflowToolkit()
        assert toolkit._siem_client is None
        assert toolkit._edr_client is None
        assert toolkit._firewall_client is None
        assert toolkit._threat_intel_client is None

    @pytest.mark.asyncio
    async def test_intake_alert_basic(self) -> None:
        toolkit = SOARWorkflowToolkit()
        alert = await toolkit.intake_alert({
            "alert_id": "A-001",
            "source": "splunk",
            "severity": "high",
            "description": "Brute force login attempt",
            "indicators": ["10.0.0.1"],
        })
        assert alert.alert_id == "A-001"
        assert alert.source == "splunk"
        assert alert.severity == "high"
        assert len(alert.mitre_tactics) > 0

    @pytest.mark.asyncio
    async def test_intake_alert_auto_detect_tactics(self) -> None:
        toolkit = SOARWorkflowToolkit()
        alert = await toolkit.intake_alert({
            "description": "Phishing email with malware attachment",
        })
        tactics = alert.mitre_tactics
        assert any("Initial Access" in t for t in tactics) or any("Execution" in t for t in tactics)

    @pytest.mark.asyncio
    async def test_intake_alert_default_tactic(self) -> None:
        toolkit = SOARWorkflowToolkit()
        alert = await toolkit.intake_alert({
            "description": "Generic security event",
        })
        assert len(alert.mitre_tactics) > 0

    @pytest.mark.asyncio
    async def test_enrich_indicators(self) -> None:
        toolkit = SOARWorkflowToolkit()
        results = await toolkit.enrich_indicators(["10.0.0.1", "evil.com"])
        assert len(results) == 2
        assert all(isinstance(r, EnrichmentResult) for r in results)
        assert results[0].indicator == "10.0.0.1"
        assert results[1].indicator == "evil.com"
        assert all(0.0 <= r.confidence <= 1.0 for r in results)

    @pytest.mark.asyncio
    async def test_execute_containment(self) -> None:
        toolkit = SOARWorkflowToolkit()
        action = await toolkit.execute_containment("10.0.0.1", "block_ip")
        assert isinstance(action, ResponseAction)
        assert action.playbook_type == PlaybookType.CONTAINMENT
        assert action.target == "10.0.0.1"
        assert action.status in (ResponseStatus.COMPLETED, ResponseStatus.FAILED)
        assert action.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_execute_eradication(self) -> None:
        toolkit = SOARWorkflowToolkit()
        action = await toolkit.execute_eradication("host-01", "remove_malware")
        assert isinstance(action, ResponseAction)
        assert action.playbook_type == PlaybookType.ERADICATION
        assert action.target == "host-01"

    @pytest.mark.asyncio
    async def test_execute_recovery(self) -> None:
        toolkit = SOARWorkflowToolkit()
        action = await toolkit.execute_recovery("svc-web", "restore_service")
        assert isinstance(action, ResponseAction)
        assert action.playbook_type == PlaybookType.RECOVERY
        assert action.target == "svc-web"

    @pytest.mark.asyncio
    async def test_execute_containment_unknown_type(self) -> None:
        toolkit = SOARWorkflowToolkit()
        action = await toolkit.execute_containment("target", "unknown_action")
        assert isinstance(action, ResponseAction)
        assert action.playbook_type == PlaybookType.CONTAINMENT


# =====================================================================
# Node Tests
# =====================================================================


class TestNodes:
    """Tests for SOAR workflow node functions."""

    @pytest.mark.asyncio
    async def test_intake_and_classify(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "alert": {
                "alert_id": "A-100",
                "source": "siem",
                "severity": "critical",
                "description": "Lateral movement detected",
                "indicators": ["192.168.1.50"],
            },
            "reasoning_chain": [],
        }
        result = await intake_and_classify(state, toolkit)
        assert result["stage"] == "enrich"
        assert result["alert"]["alert_id"] == "A-100"
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio
    async def test_enrich_context(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "alert": {
                "alert_id": "A-100",
                "source": "siem",
                "severity": "high",
                "description": "test",
                "indicators": ["10.0.0.5"],
                "mitre_tactics": [],
            },
            "reasoning_chain": [],
        }
        result = await enrich_context(state, toolkit)
        assert result["stage"] == "contain"
        assert len(result["enrichments"]) == 1
        assert len(result["reasoning_chain"]) == 1

    @pytest.mark.asyncio
    async def test_execute_containment_node(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "enrichments": [
                {
                    "indicator": "10.0.0.1",
                    "enrichment_type": "ip_reputation",
                    "result": {"is_malicious": True, "indicator_type": "ip"},
                    "confidence": 0.9,
                },
            ],
            "actions": [],
            "total_response_time_ms": 0,
            "reasoning_chain": [],
        }
        result = await execute_containment(state, toolkit)
        assert result["stage"] == "eradicate"
        assert len(result["actions"]) >= 1
        assert result["containment_status"] in ("completed", "partial", "skipped")

    @pytest.mark.asyncio
    async def test_execute_containment_node_no_malicious(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "enrichments": [
                {
                    "indicator": "10.0.0.1",
                    "enrichment_type": "ip_reputation",
                    "result": {"is_malicious": False, "indicator_type": "ip"},
                    "confidence": 0.2,
                },
            ],
            "actions": [],
            "total_response_time_ms": 0,
            "reasoning_chain": [],
        }
        result = await execute_containment(state, toolkit)
        assert result["containment_status"] == "skipped"

    @pytest.mark.asyncio
    async def test_execute_eradication_node(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "alert": {
                "alert_id": "A-100",
                "source": "siem",
                "severity": "high",
                "description": "test",
                "indicators": [],
                "mitre_tactics": ["TA0002-Execution"],
            },
            "actions": [],
            "total_response_time_ms": 0,
            "reasoning_chain": [],
        }
        result = await execute_eradication(state, toolkit)
        assert result["stage"] == "recover"
        assert result["eradication_status"] in ("completed", "partial", "skipped")

    @pytest.mark.asyncio
    async def test_recover_and_report_node(self) -> None:
        toolkit = SOARWorkflowToolkit()
        state = {
            "alert": {
                "alert_id": "A-100",
                "source": "siem",
                "severity": "high",
                "description": "test",
                "indicators": [],
                "mitre_tactics": ["TA0002-Execution"],
            },
            "actions": [],
            "total_response_time_ms": 0,
            "reasoning_chain": [],
        }
        result = await recover_and_report(state, toolkit)
        assert result["stage"] == "lessons_learned"
        assert len(result["actions"]) == 3  # 3 recovery actions
        assert result["recovery_status"] in ("completed", "partial")
        assert len(result["lessons"]) >= 2
        assert result["total_response_time_ms"] >= 0


# =====================================================================
# Graph Tests
# =====================================================================


class TestGraph:
    """Tests for SOAR workflow graph construction."""

    def test_build_graph(self) -> None:
        toolkit = SOARWorkflowToolkit()
        graph = build_graph(toolkit)
        assert graph is not None

    def test_create_soar_workflow_graph(self) -> None:
        graph = create_soar_workflow_graph()
        assert graph is not None

    def test_graph_compiles(self) -> None:
        toolkit = SOARWorkflowToolkit()
        graph = build_graph(toolkit)
        app = graph.compile()
        assert app is not None


# =====================================================================
# Runner Tests
# =====================================================================


class TestSOARWorkflowRunner:
    """Tests for SOARWorkflowRunner."""

    def test_init(self) -> None:
        runner = SOARWorkflowRunner()
        assert runner._toolkit is not None
        assert runner._app is not None

    @pytest.mark.asyncio
    async def test_run_full_workflow(self) -> None:
        runner = SOARWorkflowRunner()
        result = await runner.run(
            request_id="REQ-001",
            alert_data={
                "alert_id": "A-200",
                "source": "datadog",
                "severity": "high",
                "description": "Malware execution detected on host-05",
                "indicators": ["10.0.0.99"],
                "mitre_tactics": ["TA0002-Execution"],
            },
        )
        assert result["request_id"] == "REQ-001"
        assert result["stage"] == "lessons_learned"
        assert len(result["actions"]) > 0
        assert len(result["lessons"]) > 0
        assert result["total_response_time_ms"] >= 0


# =====================================================================
# Prompts Tests
# =====================================================================


class TestPrompts:
    """Tests for prompt templates."""

    def test_all_prompts_are_strings(self) -> None:
        assert isinstance(SYSTEM_INTAKE, str)
        assert isinstance(SYSTEM_ENRICH, str)
        assert isinstance(SYSTEM_CONTAIN, str)
        assert isinstance(SYSTEM_ERADICATE, str)
        assert isinstance(SYSTEM_RECOVER, str)

    def test_prompts_not_empty(self) -> None:
        assert len(SYSTEM_INTAKE) > 50
        assert len(SYSTEM_ENRICH) > 50
        assert len(SYSTEM_CONTAIN) > 50
        assert len(SYSTEM_ERADICATE) > 50
        assert len(SYSTEM_RECOVER) > 50
