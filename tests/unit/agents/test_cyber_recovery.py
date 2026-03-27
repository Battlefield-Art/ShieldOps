"""Tests for shieldops.agents.cyber_recovery."""

from __future__ import annotations

import pytest

from shieldops.agents.cyber_recovery.models import (
    CleanRoomValidation,
    CyberRecoveryState,
    DamageAssessment,
    IntegrityVerification,
    ReasoningStep,
    RecoveryExecution,
    RecoveryPoint,
    RecoveryStage,
    RecoveryType,
    ValidationStatus,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TestEnums:
    def test_recovery_stage_values(self) -> None:
        assert RecoveryStage.ASSESS_DAMAGE == "assess_damage"
        assert RecoveryStage.SELECT_RECOVERY_POINTS == "select_recovery_points"
        assert RecoveryStage.VALIDATE_CLEAN_ROOM == "validate_clean_room"
        assert RecoveryStage.EXECUTE_RECOVERY == "execute_recovery"
        assert RecoveryStage.VERIFY_INTEGRITY == "verify_integrity"
        assert RecoveryStage.REPORT == "report"
        assert len(RecoveryStage) == 6

    def test_recovery_type_values(self) -> None:
        assert RecoveryType.FULL_RESTORE == "full_restore"
        assert RecoveryType.GRANULAR_RESTORE == "granular_restore"
        assert RecoveryType.CLEAN_ROOM == "clean_room"
        assert RecoveryType.PARALLEL_RECOVERY == "parallel_recovery"
        assert RecoveryType.FAILOVER == "failover"
        assert len(RecoveryType) == 5

    def test_validation_status_values(self) -> None:
        assert ValidationStatus.CLEAN == "clean"
        assert ValidationStatus.INFECTED == "infected"
        assert ValidationStatus.SUSPICIOUS == "suspicious"
        assert ValidationStatus.UNTESTED == "untested"
        assert len(ValidationStatus) == 4


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class TestModels:
    def test_state_defaults(self) -> None:
        state = CyberRecoveryState()
        assert state.tenant_id == ""
        assert state.incident_id == ""
        assert state.recovery_type == RecoveryType.FULL_RESTORE
        assert isinstance(state.damage, DamageAssessment)
        assert state.damage_scope == {}
        assert state.recovery_points == []
        assert state.selected_point_id == ""
        assert state.validations == []
        assert state.has_clean_point is False
        assert state.recoveries_executed == []
        assert state.recovery_success is False
        assert state.integrity_verified is False
        assert state.rto_seconds == 0.0
        assert state.rpo_seconds == 0.0
        assert state.rto_target_seconds == 3600.0
        assert state.rpo_target_seconds == 900.0
        assert state.error == ""

    def test_damage_assessment_defaults(self) -> None:
        da = DamageAssessment()
        assert da.affected_systems == []
        assert da.encrypted_assets == []
        assert da.data_exfiltrated is False
        assert da.blast_radius == 0

    def test_recovery_point_defaults(self) -> None:
        rp = RecoveryPoint()
        assert rp.validation_status == ValidationStatus.UNTESTED
        assert rp.is_immutable is False
        assert rp.encryption_intact is True

    def test_clean_room_validation_defaults(self) -> None:
        crv = CleanRoomValidation()
        assert crv.malware_detected is False
        assert crv.validation_status == ValidationStatus.UNTESTED
        assert crv.confidence == 0.0

    def test_recovery_execution_defaults(self) -> None:
        re = RecoveryExecution()
        assert re.recovery_type == RecoveryType.FULL_RESTORE
        assert re.success is False
        assert re.data_restored_gb == 0.0

    def test_integrity_verification_defaults(self) -> None:
        iv = IntegrityVerification()
        assert iv.checksum_valid is False
        assert iv.services_healthy is False
        assert iv.data_consistency is False
        assert iv.no_malware_reinfection is False
        assert iv.application_functional is False
        assert iv.verification_score == 0.0

    def test_reasoning_step_requires_fields(self) -> None:
        step = ReasoningStep(
            step_number=1,
            action="assess",
            input_summary="in",
            output_summary="out",
        )
        assert step.step_number == 1


# ---------------------------------------------------------------------------
# Toolkit
# ---------------------------------------------------------------------------


class TestToolkit:
    @pytest.fixture()
    def toolkit(self):
        from shieldops.agents.cyber_recovery.tools import CyberRecoveryToolkit

        return CyberRecoveryToolkit()

    @pytest.mark.asyncio
    async def test_assess_damage(self, toolkit) -> None:
        result = await toolkit.assess_damage("tenant-1", "inc-001")
        assert isinstance(result, dict)
        assert "affected_systems" in result
        assert len(result["affected_systems"]) >= 1

    @pytest.mark.asyncio
    async def test_list_recovery_points(self, toolkit) -> None:
        result = await toolkit.list_recovery_points("tenant-1", ["db-primary"])
        assert isinstance(result, list)
        assert len(result) >= 1

    @pytest.mark.asyncio
    async def test_scan_clean_room(self, toolkit) -> None:
        result = await toolkit.scan_clean_room("rp-001", ["ioc-hash-abc"])
        assert isinstance(result, dict)
        assert "validation_status" in result

    @pytest.mark.asyncio
    async def test_execute_recovery(self, toolkit) -> None:
        result = await toolkit.execute_recovery(
            recovery_point_id="rp-001",
            target_system="db-primary",
            recovery_type="full_restore",
            cloud_provider="aws",
        )
        assert isinstance(result, dict)
        assert "success" in result

    @pytest.mark.asyncio
    async def test_verify_integrity(self, toolkit) -> None:
        result = await toolkit.verify_integrity("rec-001", "db-primary")
        assert isinstance(result, dict)
        assert "verification_score" in result

    @pytest.mark.asyncio
    async def test_record_recovery_metric(self, toolkit) -> None:
        await toolkit.record_recovery_metric(
            metric_type="recovery.rto_actual",
            value=1200.0,
        )
        # No exception = success


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


class TestGraph:
    def test_graph_compiles(self) -> None:
        from shieldops.agents.cyber_recovery.graph import create_cyber_recovery_graph

        graph = create_cyber_recovery_graph()
        compiled = graph.compile()
        assert compiled is not None

    def test_should_execute_recovery_routes_on_error(self) -> None:
        from shieldops.agents.cyber_recovery.graph import should_execute_recovery

        state = CyberRecoveryState(error="broken")
        assert should_execute_recovery(state) == "report"

    def test_should_execute_recovery_routes_on_clean(self) -> None:
        from shieldops.agents.cyber_recovery.graph import should_execute_recovery

        state = CyberRecoveryState(has_clean_point=True)
        assert should_execute_recovery(state) == "execute_recovery"

    def test_should_execute_recovery_routes_no_clean(self) -> None:
        from shieldops.agents.cyber_recovery.graph import should_execute_recovery

        state = CyberRecoveryState(has_clean_point=False)
        assert should_execute_recovery(state) == "report"

    def test_should_verify_routes_on_success(self) -> None:
        from shieldops.agents.cyber_recovery.graph import should_verify

        state = CyberRecoveryState(recovery_success=True)
        assert should_verify(state) == "verify_integrity"

    def test_should_verify_routes_on_failure(self) -> None:
        from shieldops.agents.cyber_recovery.graph import should_verify

        state = CyberRecoveryState(recovery_success=False)
        assert should_verify(state) == "report"
