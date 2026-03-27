"""Tests for shieldops.agents.soar_workflow."""

from __future__ import annotations

from shieldops.agents.soar_workflow.models import (
    PlaybookType,
    ResponseStage,
    ResponseStatus,
    SOARWorkflowState,
)


class TestEnums:
    def test_responsestage_intake(self):
        assert ResponseStage.INTAKE == "intake"

    def test_responsestage_enrich(self):
        assert ResponseStage.ENRICH == "enrich"

    def test_responsestage_contain(self):
        assert ResponseStage.CONTAIN == "contain"

    def test_responsestage_eradicate(self):
        assert ResponseStage.ERADICATE == "eradicate"

    def test_playbooktype_containment(self):
        assert PlaybookType.CONTAINMENT == "containment"

    def test_playbooktype_eradication(self):
        assert PlaybookType.ERADICATION == "eradication"

    def test_playbooktype_recovery(self):
        assert PlaybookType.RECOVERY == "recovery"

    def test_playbooktype_notification(self):
        assert PlaybookType.NOTIFICATION == "notification"

    def test_responsestatus_pending(self):
        assert ResponseStatus.PENDING == "pending"

    def test_responsestatus_in_progress(self):
        assert ResponseStatus.IN_PROGRESS == "in_progress"

    def test_responsestatus_completed(self):
        assert ResponseStatus.COMPLETED == "completed"

    def test_responsestatus_failed(self):
        assert ResponseStatus.FAILED == "failed"


class TestModels:
    def test_state_defaults(self):
        s = SOARWorkflowState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.soar_workflow.graph import (
            create_soar_workflow_graph,
        )

        sg = create_soar_workflow_graph()
        assert sg.compile() is not None
