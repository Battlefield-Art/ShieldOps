"""Tests for shieldops.agents.backup_security_posture."""

from __future__ import annotations

from shieldops.agents.backup_security_posture.models import (
    BackupComponent,
    BackupPostureStage,
    BackupSecurityPostureState,
    HardeningPriority,
)


class TestEnums:
    def test_backupposturestage_inventory_backup_infra(self):
        assert BackupPostureStage.INVENTORY_BACKUP_INFRA == "inventory_backup_infra"

    def test_backupposturestage_assess_security_config(self):
        assert BackupPostureStage.ASSESS_SECURITY_CONFIG == "assess_security_config"

    def test_backupposturestage_detect_vulnerabilities(self):
        assert BackupPostureStage.DETECT_VULNERABILITIES == "detect_vulnerabilities"

    def test_backupposturestage_test_recovery(self):
        assert BackupPostureStage.TEST_RECOVERY == "test_recovery"

    def test_backupcomponent_storage(self):
        assert BackupComponent.STORAGE == "storage"

    def test_backupcomponent_network(self):
        assert BackupComponent.NETWORK == "network"

    def test_backupcomponent_access_control(self):
        assert BackupComponent.ACCESS_CONTROL == "access_control"

    def test_backupcomponent_encryption(self):
        assert BackupComponent.ENCRYPTION == "encryption"

    def test_hardeningpriority_critical(self):
        assert HardeningPriority.CRITICAL == "critical"

    def test_hardeningpriority_high(self):
        assert HardeningPriority.HIGH == "high"

    def test_hardeningpriority_medium(self):
        assert HardeningPriority.MEDIUM == "medium"

    def test_hardeningpriority_low(self):
        assert HardeningPriority.LOW == "low"


class TestModels:
    def test_state_defaults(self):
        s = BackupSecurityPostureState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.backup_security_posture.graph import (
            create_backup_security_posture_graph,
        )

        sg = create_backup_security_posture_graph()
        assert sg.compile() is not None
