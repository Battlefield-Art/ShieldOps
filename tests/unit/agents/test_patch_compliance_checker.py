"""Tests for shieldops.agents.patch_compliance_checker."""

from __future__ import annotations

import pytest

from shieldops.agents.patch_compliance_checker.models import (
    MissingPatch,
    PatchComplianceCheckerState,
    PatchSeverity,
    PatchStage,
    PatchStatus,
    RolloutSchedule,
    SystemInventory,
)


def _state(**kw) -> PatchComplianceCheckerState:
    return PatchComplianceCheckerState(**kw)


class TestEnums:
    def test_patch_stage_values(self):
        assert PatchStage.INVENTORY_SYSTEMS == "inventory_systems"
        assert PatchStage.SCAN_PATCHES == "scan_patches"
        assert PatchStage.ASSESS_RISK == "assess_risk"
        assert PatchStage.CHECK_SLA == "check_sla"
        assert PatchStage.SCHEDULE_ROLLOUT == "schedule_rollout"
        assert PatchStage.REPORT == "report"

    def test_patch_severity_values(self):
        assert PatchSeverity.CRITICAL == "critical"
        assert PatchSeverity.HIGH == "high"
        assert PatchSeverity.MEDIUM == "medium"
        assert PatchSeverity.LOW == "low"
        assert PatchSeverity.INFORMATIONAL == "informational"

    def test_patch_status_values(self):
        assert PatchStatus.MISSING == "missing"
        assert PatchStatus.INSTALLED == "installed"
        assert PatchStatus.PENDING == "pending"
        assert PatchStatus.FAILED == "failed"
        assert PatchStatus.SCHEDULED == "scheduled"
        assert PatchStatus.EXCLUDED == "excluded"


class TestModels:
    def test_state_defaults(self):
        s = _state()
        assert s.request_id == ""
        assert s.tenant_id == ""
        assert s.stage == PatchStage.INVENTORY_SYSTEMS
        assert s.systems == []
        assert s.total_systems == 0
        assert s.missing_patches == []
        assert s.total_missing == 0
        assert s.critical_missing == 0
        assert s.risk_assessments == []
        assert s.fleet_risk_score == 0.0
        assert s.sla_violations == []
        assert s.sla_compliant_rate == 0.0
        assert s.rollout_schedule == []
        assert s.summary == ""
        assert s.compliance_rate == 0.0
        assert s.reasoning_chain == []
        assert s.error == ""

    def test_state_with_values(self):
        s = _state(total_systems=100, compliance_rate=91.4)
        assert s.total_systems == 100
        assert s.compliance_rate == 91.4

    def test_system_inventory_defaults(self):
        si = SystemInventory()
        assert si.system_id == ""
        assert si.hostname == ""
        assert si.os == ""

    def test_missing_patch_defaults(self):
        mp = MissingPatch()
        assert mp.patch_id == ""
        assert mp.severity == PatchSeverity.MEDIUM
        assert mp.status == PatchStatus.MISSING
        assert mp.cve_ids == []

    def test_rollout_schedule_defaults(self):
        r = RolloutSchedule()
        assert r.target_systems == []
        assert r.priority == 0


class TestToolkit:
    @pytest.fixture
    def toolkit(self):
        from shieldops.agents.patch_compliance_checker.tools import (
            PatchComplianceCheckerToolkit,
        )

        return PatchComplianceCheckerToolkit()

    @pytest.mark.asyncio
    async def test_inventory_systems(self, toolkit):
        result = await toolkit.inventory_systems("t-01")
        assert isinstance(result, list)
        assert len(result) >= 3

    @pytest.mark.asyncio
    async def test_scan_patches(self, toolkit):
        systems = await toolkit.inventory_systems("t-01")
        missing, total, critical = await toolkit.scan_patches(systems)
        assert isinstance(missing, list)
        assert total >= 1
        assert critical >= 1

    @pytest.mark.asyncio
    async def test_assess_risk(self, toolkit):
        systems = await toolkit.inventory_systems("t-01")
        missing, _, _ = await toolkit.scan_patches(systems)
        assessments, risk = await toolkit.assess_risk(missing, systems)
        assert isinstance(assessments, list)
        assert isinstance(risk, float)
        assert risk > 0.0

    @pytest.mark.asyncio
    async def test_check_sla(self, toolkit):
        systems = await toolkit.inventory_systems("t-01")
        missing, _, _ = await toolkit.scan_patches(systems)
        violations, rate = await toolkit.check_sla(missing)
        assert isinstance(violations, list)
        assert 0.0 <= rate <= 100.0


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.patch_compliance_checker.graph import (
            create_patch_compliance_checker_graph,
        )

        sg = create_patch_compliance_checker_graph()
        assert sg.compile() is not None
