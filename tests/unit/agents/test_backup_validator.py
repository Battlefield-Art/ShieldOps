"""Tests for shieldops.agents.backup_validator."""

from __future__ import annotations

from shieldops.agents.backup_validator.models import (
    BackupStage,
    BackupType,
    BackupValidatorState,
    ValidationStatus,
)


class TestEnums:
    def test_backupstage_inventory_backups(self):
        assert BackupStage.INVENTORY_BACKUPS == "inventory_backups"

    def test_backupstage_validate_integrity(self):
        assert BackupStage.VALIDATE_INTEGRITY == "validate_integrity"

    def test_backupstage_test_recovery(self):
        assert BackupStage.TEST_RECOVERY == "test_recovery"

    def test_backupstage_assess_gaps(self):
        assert BackupStage.ASSESS_GAPS == "assess_gaps"

    def test_backuptype_full(self):
        assert BackupType.FULL == "full"

    def test_backuptype_incremental(self):
        assert BackupType.INCREMENTAL == "incremental"

    def test_backuptype_differential(self):
        assert BackupType.DIFFERENTIAL == "differential"

    def test_backuptype_snapshot(self):
        assert BackupType.SNAPSHOT == "snapshot"

    def test_validationstatus_valid(self):
        assert ValidationStatus.VALID == "valid"

    def test_validationstatus_corrupted(self):
        assert ValidationStatus.CORRUPTED == "corrupted"

    def test_validationstatus_incomplete(self):
        assert ValidationStatus.INCOMPLETE == "incomplete"

    def test_validationstatus_missing(self):
        assert ValidationStatus.MISSING == "missing"


class TestModels:
    def test_state_defaults(self):
        s = BackupValidatorState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.backup_validator.graph import (
            create_backup_validator_graph,
        )

        sg = create_backup_validator_graph()
        assert sg.compile() is not None
