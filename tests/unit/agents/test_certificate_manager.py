"""Tests for shieldops.agents.certificate_manager."""

from __future__ import annotations

from shieldops.agents.certificate_manager.models import (
    CertificateManagerState,
    CertStage,
    CertStatus,
    RotationStatus,
)


class TestEnums:
    def test_certstage_discover_certs(self):
        assert CertStage.DISCOVER_CERTS == "discover_certs"

    def test_certstage_check_expiry(self):
        assert CertStage.CHECK_EXPIRY == "check_expiry"

    def test_certstage_validate_chains(self):
        assert CertStage.VALIDATE_CHAINS == "validate_chains"

    def test_certstage_plan_rotation(self):
        assert CertStage.PLAN_ROTATION == "plan_rotation"

    def test_certstatus_valid(self):
        assert CertStatus.VALID == "valid"

    def test_certstatus_expiring_soon(self):
        assert CertStatus.EXPIRING_SOON == "expiring_soon"

    def test_certstatus_expired(self):
        assert CertStatus.EXPIRED == "expired"

    def test_certstatus_revoked(self):
        assert CertStatus.REVOKED == "revoked"

    def test_rotationstatus_pending(self):
        assert RotationStatus.PENDING == "pending"

    def test_rotationstatus_in_progress(self):
        assert RotationStatus.IN_PROGRESS == "in_progress"

    def test_rotationstatus_completed(self):
        assert RotationStatus.COMPLETED == "completed"

    def test_rotationstatus_failed(self):
        assert RotationStatus.FAILED == "failed"


class TestModels:
    def test_state_defaults(self):
        s = CertificateManagerState(tenant_id="t-01")
        assert s.error == ""


class TestGraph:
    def test_graph_compiles(self):
        from shieldops.agents.certificate_manager.graph import (
            create_certificate_manager_graph,
        )

        sg = create_certificate_manager_graph()
        assert sg.compile() is not None
